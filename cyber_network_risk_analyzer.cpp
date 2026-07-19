#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <limits>
#include <queue>
#include <stack>
#include <string>
#include <vector>

using namespace std;

struct Device {
    int id;
    string hostname;
    string ipAddress;
    string deviceType;
    int riskScore;
    string vulnerability;
};

class CyberNetworkRiskAnalyzer {
private:
    vector<Device> devices;
    vector<vector<int>> adjacencyList;

    static string toLower(string text) {
        transform(text.begin(), text.end(), text.begin(),
                  [](unsigned char c) { return static_cast<char>(tolower(c)); });
        return text;
    }

    int findIndexById(int id) const {
        for (int i = 0; i < static_cast<int>(devices.size()); ++i) {
            if (devices[i].id == id) {
                return i;
            }
        }
        return -1;
    }

    static string riskCategory(int score) {
        if (score >= 80) return "Critical";
        if (score >= 60) return "High";
        if (score >= 40) return "Medium";
        return "Low";
    }

    static int readInteger(const string& prompt) {
        int value;
        while (true) {
            cout << prompt;
            if (cin >> value) {
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                return value;
            }

            cout << "Input harus berupa angka. Silakan coba lagi.\n";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }

    static string readText(const string& prompt) {
        string value;
        cout << prompt;
        getline(cin, value);
        return value;
    }

    void printDeviceDetail(const Device& device) const {
        cout << "\nData perangkat ditemukan\n";
        cout << "ID            : " << device.id << '\n';
        cout << "Hostname      : " << device.hostname << '\n';
        cout << "IP Address    : " << device.ipAddress << '\n';
        cout << "Jenis         : " << device.deviceType << '\n';
        cout << "Risk Score    : " << device.riskScore << '\n';
        cout << "Status Risiko : " << riskCategory(device.riskScore) << '\n';
        cout << "Kerentanan    : " << device.vulnerability << '\n';
    }

public:
    CyberNetworkRiskAnalyzer() {
        loadSampleData();
    }

    void loadSampleData() {
        devices = {
            {1, "Firewall-01", "192.168.1.1", "Firewall", 30, "Port administrasi masih terbuka"},
            {2, "Web-Server", "192.168.1.10", "Server", 85, "Versi web server sudah lama"},
            {3, "Database-Server", "192.168.1.20", "Database", 95, "Password database lemah"},
            {4, "Admin-PC", "192.168.1.30", "Client", 70, "Antivirus tidak aktif"},
            {5, "Backup-Server", "192.168.1.40", "Server", 60, "Data backup belum dienkripsi"},
            {6, "Employee-PC", "192.168.1.50", "Client", 55, "Sistem operasi belum diperbarui"}
        };

        adjacencyList.assign(devices.size(), {});

        addConnection(1, 2, false);
        addConnection(1, 4, false);
        addConnection(1, 6, false);
        addConnection(2, 3, false);
        addConnection(4, 3, false);
        addConnection(3, 5, false);
        addConnection(6, 4, false);
    }

    void addDevice() {
        Device newDevice;

        newDevice.id = readInteger("Masukkan ID perangkat: ");
        if (findIndexById(newDevice.id) != -1) {
            cout << "ID sudah digunakan. Perangkat gagal ditambahkan.\n";
            return;
        }

        newDevice.hostname = readText("Masukkan hostname: ");
        newDevice.ipAddress = readText("Masukkan IP address: ");
        newDevice.deviceType = readText("Masukkan jenis perangkat: ");

        do {
            newDevice.riskScore = readInteger("Masukkan risk score (0-100): ");
            if (newDevice.riskScore < 0 || newDevice.riskScore > 100) {
                cout << "Risk score harus berada pada rentang 0 sampai 100.\n";
            }
        } while (newDevice.riskScore < 0 || newDevice.riskScore > 100);

        newDevice.vulnerability = readText("Masukkan kerentanan: ");

        devices.push_back(newDevice);
        adjacencyList.push_back({});
        cout << "Perangkat berhasil ditambahkan.\n";
    }

    void addConnection(int sourceId, int destinationId, bool showMessage = true) {
        const int sourceIndex = findIndexById(sourceId);
        const int destinationIndex = findIndexById(destinationId);

        if (sourceIndex == -1 || destinationIndex == -1) {
            if (showMessage) {
                cout << "Salah satu ID perangkat tidak ditemukan.\n";
            }
            return;
        }

        if (sourceIndex == destinationIndex) {
            if (showMessage) {
                cout << "Perangkat tidak dapat dihubungkan dengan dirinya sendiri.\n";
            }
            return;
        }

        const auto alreadyConnected = find(
            adjacencyList[sourceIndex].begin(),
            adjacencyList[sourceIndex].end(),
            destinationIndex
        );

        if (alreadyConnected != adjacencyList[sourceIndex].end()) {
            if (showMessage) {
                cout << "Koneksi tersebut sudah tersedia.\n";
            }
            return;
        }

        // Koneksi jaringan dibuat dua arah (undirected graph).
        adjacencyList[sourceIndex].push_back(destinationIndex);
        adjacencyList[destinationIndex].push_back(sourceIndex);

        if (showMessage) {
            cout << "Koneksi berhasil ditambahkan.\n";
        }
    }

    void inputConnection() {
        const int sourceId = readInteger("Masukkan ID perangkat pertama: ");
        const int destinationId = readInteger("Masukkan ID perangkat kedua: ");
        addConnection(sourceId, destinationId);
    }

    void displayDevices() const {
        if (devices.empty()) {
            cout << "Belum ada data perangkat.\n";
            return;
        }

        cout << "\nDAFTAR PERANGKAT\n";
        cout << left
             << setw(5) << "ID"
             << setw(20) << "Hostname"
             << setw(17) << "IP Address"
             << setw(15) << "Jenis"
             << setw(12) << "Risk Score"
             << "Status\n";
        cout << string(80, '-') << '\n';

        for (const Device& device : devices) {
            cout << left
                 << setw(5) << device.id
                 << setw(20) << device.hostname
                 << setw(17) << device.ipAddress
                 << setw(15) << device.deviceType
                 << setw(12) << device.riskScore
                 << riskCategory(device.riskScore) << '\n';
        }
    }

    void displayGraph() const {
        if (devices.empty()) {
            cout << "Belum ada data graph.\n";
            return;
        }

        cout << "\nGRAPH JARINGAN (ADJACENCY LIST)\n";
        for (int i = 0; i < static_cast<int>(devices.size()); ++i) {
            cout << devices[i].hostname << " -> ";

            if (adjacencyList[i].empty()) {
                cout << "Tidak memiliki koneksi";
            } else {
                for (int j = 0; j < static_cast<int>(adjacencyList[i].size()); ++j) {
                    cout << devices[adjacencyList[i][j]].hostname;
                    if (j + 1 < static_cast<int>(adjacencyList[i].size())) {
                        cout << ", ";
                    }
                }
            }
            cout << '\n';
        }
    }

    void linearSearch() const {
        if (devices.empty()) {
            cout << "Belum ada data perangkat.\n";
            return;
        }

        cout << "\nPENCARIAN LINEAR\n";
        cout << "1. Cari berdasarkan hostname\n";
        cout << "2. Cari berdasarkan IP address\n";
        const int option = readInteger("Pilih metode pencarian: ");

        if (option != 1 && option != 2) {
            cout << "Pilihan tidak valid.\n";
            return;
        }

        const string keyword = toLower(readText("Masukkan kata kunci: "));

        for (const Device& device : devices) {
            const string comparedValue = option == 1
                ? toLower(device.hostname)
                : toLower(device.ipAddress);

            if (comparedValue == keyword) {
                printDeviceDetail(device);
                cout << "Kompleksitas pencarian: O(n)\n";
                return;
            }
        }

        cout << "Perangkat tidak ditemukan.\n";
        cout << "Kompleksitas pencarian: O(n)\n";
    }

    void binarySearchById() const {
        if (devices.empty()) {
            cout << "Belum ada data perangkat.\n";
            return;
        }

        const int targetId = readInteger("Masukkan ID perangkat yang dicari: ");
        vector<Device> sortedDevices = devices;

        sort(sortedDevices.begin(), sortedDevices.end(),
             [](const Device& a, const Device& b) {
                 return a.id < b.id;
             });

        int left = 0;
        int right = static_cast<int>(sortedDevices.size()) - 1;

        while (left <= right) {
            const int middle = left + (right - left) / 2;

            if (sortedDevices[middle].id == targetId) {
                printDeviceDetail(sortedDevices[middle]);
                cout << "Kompleksitas Binary Search: O(log n)\n";
                return;
            }

            if (sortedDevices[middle].id < targetId) {
                left = middle + 1;
            } else {
                right = middle - 1;
            }
        }

        cout << "Perangkat dengan ID tersebut tidak ditemukan.\n";
        cout << "Kompleksitas Binary Search: O(log n)\n";
    }

    void bfsShortestPath() const {
        if (devices.empty()) {
            cout << "Belum ada data graph.\n";
            return;
        }

        const int sourceId = readInteger("Masukkan ID perangkat sumber serangan: ");
        const int targetId = readInteger("Masukkan ID perangkat target: ");

        const int sourceIndex = findIndexById(sourceId);
        const int targetIndex = findIndexById(targetId);

        if (sourceIndex == -1 || targetIndex == -1) {
            cout << "ID sumber atau target tidak ditemukan.\n";
            return;
        }

        vector<bool> visited(devices.size(), false);
        vector<int> parent(devices.size(), -1);
        queue<int> deviceQueue;

        visited[sourceIndex] = true;
        deviceQueue.push(sourceIndex);

        while (!deviceQueue.empty()) {
            const int current = deviceQueue.front();
            deviceQueue.pop();

            if (current == targetIndex) {
                break;
            }

            for (int neighbor : adjacencyList[current]) {
                if (!visited[neighbor]) {
                    visited[neighbor] = true;
                    parent[neighbor] = current;
                    deviceQueue.push(neighbor);
                }
            }
        }

        if (!visited[targetIndex]) {
            cout << "Tidak ditemukan jalur koneksi menuju target.\n";
            cout << "Kompleksitas BFS: O(V + E)\n";
            return;
        }

        vector<int> path;
        for (int current = targetIndex; current != -1; current = parent[current]) {
            path.push_back(current);
        }
        reverse(path.begin(), path.end());

        cout << "\nJalur serangan terpendek menggunakan BFS:\n";
        for (int i = 0; i < static_cast<int>(path.size()); ++i) {
            cout << devices[path[i]].hostname;
            if (i + 1 < static_cast<int>(path.size())) {
                cout << " -> ";
            }
        }

        cout << "\nJumlah koneksi/hop: " << path.size() - 1 << '\n';
        cout << "Risiko target      : " << riskCategory(devices[targetIndex].riskScore)
             << " (" << devices[targetIndex].riskScore << ")\n";
        cout << "Kompleksitas BFS   : O(V + E)\n";
    }

    void dfsImpactAnalysis() const {
        if (devices.empty()) {
            cout << "Belum ada data graph.\n";
            return;
        }

        const int sourceId = readInteger("Masukkan ID perangkat yang terinfeksi: ");
        const int sourceIndex = findIndexById(sourceId);

        if (sourceIndex == -1) {
            cout << "ID perangkat tidak ditemukan.\n";
            return;
        }

        vector<bool> visited(devices.size(), false);
        stack<int> deviceStack;
        vector<int> traversalOrder;

        deviceStack.push(sourceIndex);

        while (!deviceStack.empty()) {
            const int current = deviceStack.top();
            deviceStack.pop();

            if (visited[current]) {
                continue;
            }

            visited[current] = true;
            traversalOrder.push_back(current);

            // Urutan dibalik agar traversal lebih konsisten dengan adjacency list.
            for (auto it = adjacencyList[current].rbegin();
                 it != adjacencyList[current].rend(); ++it) {
                if (!visited[*it]) {
                    deviceStack.push(*it);
                }
            }
        }

        cout << "\nPERANGKAT YANG BERPOTENSI TERDAMPAK (DFS)\n";
        for (int i = 0; i < static_cast<int>(traversalOrder.size()); ++i) {
            const Device& device = devices[traversalOrder[i]];
            cout << i + 1 << ". " << device.hostname
                 << " | IP: " << device.ipAddress
                 << " | Risiko: " << riskCategory(device.riskScore) << '\n';
        }

        cout << "Total perangkat yang dapat dijangkau: "
             << traversalOrder.size() << '\n';
        cout << "Kompleksitas DFS: O(V + E)\n";
    }

    void bubbleSortByRisk() const {
        if (devices.empty()) {
            cout << "Belum ada data perangkat.\n";
            return;
        }

        vector<Device> sortedDevices = devices;
        const int n = static_cast<int>(sortedDevices.size());

        for (int i = 0; i < n - 1; ++i) {
            bool swapped = false;

            for (int j = 0; j < n - i - 1; ++j) {
                if (sortedDevices[j].riskScore < sortedDevices[j + 1].riskScore) {
                    swap(sortedDevices[j], sortedDevices[j + 1]);
                    swapped = true;
                }
            }

            if (!swapped) {
                break;
            }
        }

        cout << "\nURUTAN PRIORITAS RISIKO (BUBBLE SORT DESCENDING)\n";
        cout << left
             << setw(5) << "No"
             << setw(20) << "Hostname"
             << setw(12) << "Risk Score"
             << setw(12) << "Status"
             << "Kerentanan\n";
        cout << string(90, '-') << '\n';

        for (int i = 0; i < n; ++i) {
            cout << left
                 << setw(5) << i + 1
                 << setw(20) << sortedDevices[i].hostname
                 << setw(12) << sortedDevices[i].riskScore
                 << setw(12) << riskCategory(sortedDevices[i].riskScore)
                 << sortedDevices[i].vulnerability << '\n';
        }

        cout << "Kompleksitas Bubble Sort: O(n^2)\n";
    }

    static void displayBigOAnalysis() {
        cout << "\nANALISIS BIG O\n";
        cout << left
             << setw(32) << "Fitur"
             << setw(22) << "Algoritma"
             << "Kompleksitas\n";
        cout << string(70, '-') << '\n';
        cout << left << setw(32) << "Menampilkan data perangkat"
             << setw(22) << "Traversal" << "O(n)\n";
        cout << left << setw(32) << "Mencari hostname/IP"
             << setw(22) << "Linear Search" << "O(n)\n";
        cout << left << setw(32) << "Mencari ID terurut"
             << setw(22) << "Binary Search" << "O(log n)\n";
        cout << left << setw(32) << "Mencari jalur terpendek"
             << setw(22) << "BFS" << "O(V + E)\n";
        cout << left << setw(32) << "Menelusuri dampak serangan"
             << setw(22) << "DFS" << "O(V + E)\n";
        cout << left << setw(32) << "Mengurutkan tingkat risiko"
             << setw(22) << "Bubble Sort" << "O(n^2)\n";

        cout << "\nKeterangan:\n";
        cout << "n = jumlah data perangkat\n";
        cout << "V = jumlah vertex/perangkat\n";
        cout << "E = jumlah edge/koneksi jaringan\n";
    }

    void run() {
        int menu;

        do {
            cout << "\n====================================================\n";
            cout << "          CYBER NETWORK RISK ANALYZER\n";
            cout << "====================================================\n";
            cout << "1. Tampilkan semua perangkat\n";
            cout << "2. Tampilkan graph jaringan\n";
            cout << "3. Tambah perangkat\n";
            cout << "4. Tambah koneksi antarperangkat\n";
            cout << "5. Cari perangkat (Linear Search)\n";
            cout << "6. Cari perangkat berdasarkan ID (Binary Search)\n";
            cout << "7. Cari jalur serangan terpendek (BFS)\n";
            cout << "8. Analisis perangkat terdampak (DFS)\n";
            cout << "9. Urutkan perangkat berdasarkan risiko (Bubble Sort)\n";
            cout << "10. Tampilkan analisis Big O\n";
            cout << "0. Keluar\n";
            cout << "====================================================\n";

            menu = readInteger("Pilih menu: ");

            switch (menu) {
                case 1:
                    displayDevices();
                    break;
                case 2:
                    displayGraph();
                    break;
                case 3:
                    addDevice();
                    break;
                case 4:
                    inputConnection();
                    break;
                case 5:
                    linearSearch();
                    break;
                case 6:
                    binarySearchById();
                    break;
                case 7:
                    bfsShortestPath();
                    break;
                case 8:
                    dfsImpactAnalysis();
                    break;
                case 9:
                    bubbleSortByRisk();
                    break;
                case 10:
                    displayBigOAnalysis();
                    break;
                case 0:
                    cout << "Program selesai. Terima kasih.\n";
                    break;
                default:
                    cout << "Menu tidak tersedia.\n";
            }
        } while (menu != 0);
    }
};

int main() {
    CyberNetworkRiskAnalyzer application;
    application.run();
    return 0;
}
