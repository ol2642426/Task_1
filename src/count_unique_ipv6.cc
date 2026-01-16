#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>
#include <cstdio>
#include <atomic>
#include <mutex>
#include <thread>
#include <iomanip>

// Структура для хранения IPv6 как 128-битного числа (2 x 64 бита)
struct uint128_t {
    uint64_t hi;
    uint64_t lo;

    // Операторы сравнения для сортировки и уникальности
    bool operator<(const uint128_t& other) const {
        if (hi != other.hi) return hi < other.hi;
        return lo < other.lo;
    }

    bool operator==(const uint128_t& other) const {
        return hi == other.hi && lo == other.lo;
    }
};

// Константы
const size_t NUM_BUCKETS = 256;
const size_t WRITE_BUFFER_SIZE = 1024 * 64; // Буфер записи для каждого бакета (в элементах)

// Глобальный счетчик уникальных адресов
std::atomic<uint64_t> total_unique_count{0};

// --- ПАРСЕР IP АДРЕСОВ ---

// Вспомогательная функция для конвертации hex-символа в число
inline int hexDigitToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Ручной парсер IPv6.
// Преобразует строку в uint128_t. Автоматически приводит к каноническому бинарному виду.
bool parseIPv6(const std::string& line, uint128_t& result) {
    uint16_t parts[8] = {0};
    int current_part = 0;
    int double_colon_index = -1; // Индекс, где встретилось ::
    
    size_t i = 0;
    size_t len = line.length();
    
    // Пропускаем возможные пробелы в начале
    while (i < len && isspace(line[i])) i++;

    if (i == len) return false;

    // Особая обработка, если адрес начинается с ::
    if (line[i] == ':') {
        if (i + 1 < len && line[i+1] == ':') {
            double_colon_index = 0;
            i += 2;
            // Если строка просто "::", то это 0
            if (i >= len || isspace(line[i])) {
                 result.hi = 0; result.lo = 0;
                 return true;
            }
        } else {
            // Невалидный адрес (начался с одиночного :)
            return false;
        }
    }

    while (i < len && current_part < 8) {
        // Читаем hex число
        uint32_t val = 0;
        bool has_digits = false;
        
        while (i < len) {
            int digit = hexDigitToInt(line[i]);
            if (digit == -1) break;
            val = (val << 4) | digit;
            has_digits = true;
            i++;
        }

        if (has_digits) {
            parts[current_part++] = static_cast<uint16_t>(val);
        }

        if (i >= len || isspace(line[i])) break;

        if (line[i] == ':') {
            i++;
            if (i < len && line[i] == ':') {
                if (double_colon_index != -1) return false; // Второе :: запрещено
                double_colon_index = current_part;
                i++;
            }
        } else {
            return false; // Некорректный символ
        }
    }

    // Раскрытие :: (double colon)
    if (double_colon_index != -1) {
        int parts_parsed = current_part;
        int parts_to_shift = parts_parsed - double_colon_index;
        int shift_amount = 8 - parts_parsed;
        
        for (int k = 0; k < parts_to_shift; ++k) {
            parts[7 - k] = parts[parts_parsed - 1 - k];
            parts[parts_parsed - 1 - k] = 0;
        }
    } else if (current_part != 8) {
        return false; // Не полный адрес и нет ::
    }

    // Упаковка в 2 uint64
    result.hi = ((uint64_t)parts[0] << 48) | ((uint64_t)parts[1] << 32) | 
                ((uint64_t)parts[2] << 16) | ((uint64_t)parts[3]);
    result.lo = ((uint64_t)parts[4] << 48) | ((uint64_t)parts[5] << 32) | 
                ((uint64_t)parts[6] << 16) | ((uint64_t)parts[7]);

    return true;
}

// --- УПРАВЛЕНИЕ ФАЙЛАМИ ---
std::string getBucketFileName(size_t bucket_id) {
    return "temp_bucket_" + std::to_string(bucket_id) + ".bin";
}

// Класс для буферизированной записи в бакеты
class BucketWriter {
    std::vector<std::ofstream> streams;
    std::vector<std::vector<uint128_t>> buffers;

public:
    BucketWriter() {
        streams.resize(NUM_BUCKETS);
        buffers.resize(NUM_BUCKETS);
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            buffers[i].reserve(WRITE_BUFFER_SIZE);
        }
    }

    void openAll() {
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            std::string file_name = getBucketFileName(i);
            streams[i].open(file_name, std::ios::binary | std::ios::out | std::ios::trunc);
            if (!streams[i].is_open()) {
                std::cerr << "Error: Could not open temp file " << file_name << std::endl;
                exit(1);
            }
        }
    }

    void add(uint8_t bucket_idx, const uint128_t& ip) {
        buffers[bucket_idx].push_back(ip);
        if (buffers[bucket_idx].size() >= WRITE_BUFFER_SIZE) {
            flush(bucket_idx);
        }
    }

    void flush(size_t bucket_idx) {
        if (buffers[bucket_idx].empty()) return;
        streams[bucket_idx].write(reinterpret_cast<char*>(buffers[bucket_idx].data()), 
                                  buffers[bucket_idx].size() * sizeof(uint128_t));
        buffers[bucket_idx].clear();
    }

    void flushAllAndClose() {
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            flush(i);
            streams[i].close();
        }
    }
};

// --- ОБРАБОТКА БАКЕТОВ ---
void processBucket(size_t bucket_idx) {
    std::string fname = getBucketFileName(bucket_idx);
    std::ifstream infile(fname, std::ios::binary | std::ios::ate);
    
    if (!infile.is_open()) return;

    std::streamsize size = infile.tellg();
    infile.seekg(0, std::ios::beg);

    if (size == 0) {
        std::remove(fname.c_str());
        return;
    }

    size_t count = size / sizeof(uint128_t);
    std::vector<uint128_t> ips(count);

    infile.read(reinterpret_cast<char*>(ips.data()), size);
    infile.close();

    // Сортировка и подсчет уникальных значений
    std::sort(ips.begin(), ips.end());
    
    // std::unique перемещает уникальные элементы в начало и возвращает итератор на новый конец
    auto last = std::unique(ips.begin(), ips.end());
    
    // Количество уникальных элементов
    size_t unique_in_bucket = std::distance(ips.begin(), last);
    
    total_unique_count += unique_in_bucket;

    // Удаляем временный файл
    std::remove(fname.c_str());
}

// --- MAIN ---
int main(int argc, char* argv[]) {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    if (argc != 3) {
        std::cerr << "Usage in format: " << argv[0] << " <input_file> <output_file>" << std::endl;
        return 1;
    }

    std::string inputPath = argv[1];
    std::string outputPath = argv[2];

    // Фаза 1: Чтение и разделение
    std::cout << "Phase 1: Reading file and partitioning..." << std::endl;
    
    std::ifstream inFile(inputPath);
    if (!inFile.is_open()) {
        std::cerr << "Error: Could not open input file." << std::endl;
        return 1;
    }

    BucketWriter writer;
    writer.openAll();

    std::string line;
    uint128_t ipVal;
    uint64_t processedLines = 0;

    while (std::getline(inFile, line)) {
        if (line.empty()) continue;
        
        // Удаляем CR в конце, если они есть
        if (line.back() == '\r') line.pop_back(); 

        if (parseIPv6(line, ipVal)) {
            // Используем старший байт как индекс корзины (0-255)
            uint8_t bucketIdx = (ipVal.hi >> 56) & 0xFF;
            writer.add(bucketIdx, ipVal);
        }
        
        processedLines++;
        if (processedLines % 10000000 == 0) {
            std::cout << "Processed over " << processedLines << " lines..." << std::endl;
        }
    }
    
    writer.flushAllAndClose();
    inFile.close();

    // Фаза 2: Параллельная обработка бакетов
    std::cout << "Phase 2: Counting uniques in buckets..." << std::endl;

    unsigned int nThreads = std::thread::hardware_concurrency();
    if (nThreads == 0) nThreads = 4;
    
    std::vector<std::thread> threads;
    std::atomic<size_t> currentBucket{0};

    // Функция-воркер для потоков
    auto worker = [&]() {
        while (true) {
            size_t b = currentBucket.fetch_add(1);
            if (b >= NUM_BUCKETS) break;
            processBucket(b);
        }
    };

    for (unsigned int i = 0; i < nThreads; ++i) {
        threads.emplace_back(worker);
    }

    for (auto& t : threads) {
        t.join();
    }

    // Вывод результата
    std::ofstream outFile(outputPath);
    if (outFile.is_open()) {
        outFile << total_unique_count.load() << std::endl;
        outFile.close();
    } else {
        std::cerr << "Error: Could not write output file." << std::endl;
    }

    std::cout << "Done. Found " << total_unique_count.load() << " unique IPv6 addresses." << std::endl;

    return 0;
}
