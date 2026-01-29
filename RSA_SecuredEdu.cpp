#include <iostream>
#include <fstream>
#include <cstring>
#include <cmath>
#include <ctime>
#include <cstdlib>
#include <windows.h>
#include <iomanip>

using namespace std;

//  CONSTANTS 
const int MAX_USERS = 100;
const int MAX_CLASSES = 50;
const int MAX_EXAMS = 50;
const int MAX_ASSIGNMENTS = 100;
const int MAX_messagesList = 100;
const int MAX_REQUESTS = 100;
const int MAX_KEYS = 100;
const int BOX_WIDTH = 60;

//  STRUCTURES
struct RSAKeys {
    long long n;
    long long e;
    long long d;
    long long p;  //  key info display
    long long q;  //  key info display
    long long phi; // educational purposes
};

struct DigitalSignature {
    char signedBy[50];
    long long signatureHash;
    bool isVerified;
};

struct User {
    char username[50];
    char password[50];
    char role[20];
    RSAKeys keys;
    bool isActive;
};

struct Classroom {
    char classId[20];
    char className[100];
    char classCode[10];
    char teacherName[50];
    char enrolledStudents[50][50];
    int studentCount;
    char assignedExams[20][20];
    int examCount;
    bool isActive;
};

struct Exam {
    char id[20];
    char title[100];
    char encryptedContent[5000];
    char teacherName[50];
    char assignedClassId[20];
    char assignedClassName[100];
    int duration;
    bool isActive;
    char approvedStudents[50][50];
    int approvedCount;
    bool keyDistributed;
    DigitalSignature signature;  //  digital signature
  
    long long exam_n; // Unique Modulus for this exam
    long long exam_e; // Unique Public Exponent
    long long exam_d; // Unique Private Key (The target for cracking)
    long long exam_p; // Prime P (For hint/leak)
    long long exam_q; // Prime Q (For hint/leak)
};

struct Assignment {
    char id[20];
    char studentName[50];
    char courseName[100];
    char encryptedSubmission[5000];
    char encryptedGrade[1000];
    bool isGraded;
    DigitalSignature signature;  // Added digital signature
};

struct Message {
    char id[20];
    char from[50];
    char to[50];
    char encryptedContent[2000];
    bool isRead;
    long long integrityHash;  // Added for integrity check
};

struct AccessRequest {
    char id[20];
    char studentName[50];
    char examId[20];
    char examTitle[100];
    char teacherName[50];
    char classId[20];
    char status[20];
    char message[500];
};

struct KeyDistribution {
    char id[20];
    char examId[20];
    char examTitle[100];
    char classId[20];
    char className[100];
    char fromTeacher[50];
    char toStudent[50];
    long long publicKeyE;
    long long publicKeyN;
    long long p; // Prime P (for student cracking)
    long long q; // Prime Q (for student cracking)
    bool isClassWide;
    bool isRead;
};

//  GLOBAL ARRAYS 
User users[MAX_USERS];
int userCount = 0;
Classroom classes[MAX_CLASSES];
int classCount = 0;
Exam exams[MAX_EXAMS];
int examCount = 0;
Assignment assignments[MAX_ASSIGNMENTS];
int assignmentCount = 0;
Message messagesList[MAX_messagesList];
int messageCount = 0;
AccessRequest requests[MAX_REQUESTS];
int requestCount = 0;
KeyDistribution keyDist[MAX_KEYS];
int keyDistCount = 0;

//  GLOBAL VARIABLES
char currentUser[50] = "";
char currentRole[20] = "";
int idCounter = 1000;

//COLOR CODES
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
const int COLOR_DEFAULT = 7;
const int COLOR_HEADER = 10;
const int COLOR_ERROR = 12;
const int COLOR_INFO = 14;
const int COLOR_BORDER = 9;
const int COLOR_SUCCESS = 11;
const int COLOR_TITLE = 13;    // Magenta for titles
const int COLOR_BOX = 3;       // Cyan for boxes

void setColor(int color) {
    SetConsoleTextAttribute(hConsole, color);
}

void resetColor() {
    setColor(COLOR_DEFAULT);
}

//  CONSOLE UTILITIES
void getConsoleDimensions(int& width, int& height) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
}

void printCentered(const char* text, int width = 0) {
    int consoleWidth, dummyHeight;
    getConsoleDimensions(consoleWidth, dummyHeight);
    if (width == 0) width = consoleWidth;
    int textLength = strlen(text);
    int padding = (width - textLength) / 2;
    if (padding < 0) padding = 0;
    for (int i = 0; i < padding; i++) cout << " ";
    cout << text;
}

void centerText(const char* text) {
    printCentered(text);
    cout << endl;
}

//  BOX DRAWING UTILITIES 
void drawHorizontalLine(char left, char mid, char right, int width) {
    int consoleWidth, dummyHeight;
    getConsoleDimensions(consoleWidth, dummyHeight);
    int padding = (consoleWidth - width) / 2;
    for (int i = 0; i < padding; i++) cout << " ";
    
    cout << left;
    for (int i = 0; i < width - 2; i++) cout << mid;
    cout << right << endl;
}

void drawBoxTop(int width = BOX_WIDTH) {
    setColor(COLOR_BOX);
    drawHorizontalLine('+', '-', '+', width);
    resetColor();
}
void syncIdCounter() {
    int maxId = 1000;

    // Check Classes (CLSxxxx)
    for (int i = 0; i < classCount; i++) {
        // Skip the first 3 chars ("CLS") and convert the rest to int
        int currentId = atoi(classes[i].classId + 3); 
        if (currentId > maxId) maxId = currentId;
    }

    // Check Exams (EXAMxxxx) - purely to be safe since they share the counter
    for (int i = 0; i < examCount; i++) {
        // Skip the first 4 chars ("EXAM")
        int currentId = atoi(exams[i].id + 4);
        if (currentId > maxId) maxId = currentId;
    }

    // Set the global counter to 1 higher than the highest existing ID
    idCounter = maxId + 1;
}
void drawBoxBottom(int width = BOX_WIDTH) {
    setColor(COLOR_BOX);
    drawHorizontalLine('+', '-', '+', width);
    resetColor();
}

void drawBoxMiddle(int width = BOX_WIDTH) {
    setColor(COLOR_BOX);
    drawHorizontalLine('+', '-', '+', width);
    resetColor();
}

void drawBoxLine(const char* text, int width = BOX_WIDTH, int color = COLOR_DEFAULT) {
    int consoleWidth, dummyHeight;
    getConsoleDimensions(consoleWidth, dummyHeight);
    int padding = (consoleWidth - width) / 2;
    
    for (int i = 0; i < padding; i++) cout << " ";
    
    setColor(COLOR_BOX);
    cout << "|";
    resetColor();
    
    setColor(color);
    int textLen = strlen(text);
    int innerWidth = width - 2;
    int leftPad = (innerWidth - textLen) / 2;
    int rightPad = innerWidth - textLen - leftPad;
    
    for (int i = 0; i < leftPad; i++) cout << " ";
    cout << text;
    for (int i = 0; i < rightPad; i++) cout << " ";
    
    setColor(COLOR_BOX);
    cout << "|" << endl;
    resetColor();
}

void drawBoxLineLeft(const char* text, int width = BOX_WIDTH, int color = COLOR_DEFAULT) {
    int consoleWidth, dummyHeight;
    getConsoleDimensions(consoleWidth, dummyHeight);
    int padding = (consoleWidth - width) / 2;
    
    for (int i = 0; i < padding; i++) cout << " ";
    
    setColor(COLOR_BOX);
    cout << "| ";
    resetColor();
    
    setColor(color);
    int textLen = strlen(text);
    int innerWidth = width - 4;
    cout << text;
    for (int i = textLen; i < innerWidth; i++) cout << " ";
    
    setColor(COLOR_BOX);
    cout << " |" << endl;
    resetColor();
}

void drawEmptyBoxLine(int width = BOX_WIDTH) {
    drawBoxLine("", width);
}

//  TABLE DRAWING UTILITIES 
void drawTableHeader(const char* headers[], int colCount, int colWidths[], int totalWidth = BOX_WIDTH) {
    int consoleWidth, dummyHeight;
    getConsoleDimensions(consoleWidth, dummyHeight);
    int padding = (consoleWidth - totalWidth) / 2;
    
    // Top border
    for (int i = 0; i < padding; i++) cout << " ";
    setColor(COLOR_BOX);
    cout << "+";
    for (int c = 0; c < colCount; c++) {
        for (int i = 0; i < colWidths[c]; i++) cout << "-";
        cout << "+";
    }
    cout << endl;
    
    // Header text
    for (int i = 0; i < padding; i++) cout << " ";
    cout << "|";
    setColor(COLOR_HEADER);
    for (int c = 0; c < colCount; c++) {
        int textLen = strlen(headers[c]);
        int leftPad = (colWidths[c] - textLen) / 2;
        int rightPad = colWidths[c] - textLen - leftPad;
        for (int i = 0; i < leftPad; i++) cout << " ";
        cout << headers[c];
        for (int i = 0; i < rightPad; i++) cout << " ";
        setColor(COLOR_BOX);
        cout << "|";
        setColor(COLOR_HEADER);
    }
    cout << endl;
    
    // Separator
    for (int i = 0; i < padding; i++) cout << " ";
    setColor(COLOR_BOX);
    cout << "+";
    for (int c = 0; c < colCount; c++) {
        for (int i = 0; i < colWidths[c]; i++) cout << "=";
        cout << "+";
    }
    cout << endl;
    resetColor();
}

void drawTableRow(const char* cells[], int colCount, int colWidths[], int totalWidth = BOX_WIDTH) {
    int consoleWidth, dummyHeight;
    getConsoleDimensions(consoleWidth, dummyHeight);
    int padding = (consoleWidth - totalWidth) / 2;
    
    for (int i = 0; i < padding; i++) cout << " ";
    setColor(COLOR_BOX);
    cout << "|";
    resetColor();
    
    for (int c = 0; c < colCount; c++) {
        int textLen = strlen(cells[c]);
        int displayLen = (textLen > colWidths[c] - 2) ? colWidths[c] - 2 : textLen;
        cout << " ";
        for (int i = 0; i < displayLen; i++) cout << cells[c][i];
        for (int i = displayLen; i < colWidths[c] - 1; i++) cout << " ";
        setColor(COLOR_BOX);
        cout << "|";
        resetColor();
    }
    cout << endl;
}

void drawTableBottom(int colCount, int colWidths[], int totalWidth = BOX_WIDTH) {
    int consoleWidth, dummyHeight;
    getConsoleDimensions(consoleWidth, dummyHeight);
    int padding = (consoleWidth - totalWidth) / 2;
    
    for (int i = 0; i < padding; i++) cout << " ";
    setColor(COLOR_BOX);
    cout << "+";
    for (int c = 0; c < colCount; c++) {
        for (int i = 0; i < colWidths[c]; i++) cout << "-";
        cout << "+";
    }
    cout << endl;
    resetColor();
}

// ============= ASCII ART HEADERS =============
void displayMainBanner() {
    setColor(COLOR_TITLE);
    centerText("");
    centerText("  ____  ____  ____  _  _  ____  ____    ____  ____  _  _ ");
    centerText(" / ___)(  __)(  __)/ )( \\(  _ \\(  __)  (  __)(    \\/ )( \\");
    centerText(" \\___ \\ ) _)  ) _) ) \\/ ( )   / ) _)    ) _)  ) D () \\/ (");
    centerText(" (____/(____)(____)\\_)(_((__\\_)(____))__(____)(____/\\____/");
    centerText("                                   (__)                   ");
    resetColor();
}

void displayTeacherBanner() {
    setColor(COLOR_HEADER);
    centerText("");
    centerText(" _____ ____   __    ___  _   _ ____  ____  ");
    centerText("|_   _| ___| / _\\  / __|| | | || ___|| _  \\");
    centerText("  | | | _|  | |_| | |   | |_| || _|  |   _/");
    centerText("  |_| |____||_| |_||___||_| |_||____||_|\\_\\");
    centerText("           PORTAL                          ");
    resetColor();
}

void displayStudentBanner() {
    setColor(COLOR_SUCCESS);
    centerText("");
    centerText(" ____  _____  _   _  ____   ____  _   _  _____ ");
    centerText("/ ___||_   _|| | | || _  \\ | ___|| \\ | ||_   _|");
    centerText("\\___ \\  | |  | | | || | | || _|  |  \\| |  | |  ");
    centerText(" ___) | | |  | |_| || |_| || |___| |\\  |  | |  ");
    centerText("|____/  |_|   \\___/ |____/ |_____|_| \\_|  |_|  ");
    centerText("           PORTAL                              ");
    resetColor();
}

void displayRSABanner() {
    setColor(COLOR_INFO);
    centerText("");
    centerText(" ____   ____    _    ");
    centerText("|  _ \\ / ___|  / \\   ");
    centerText("| |_) |\\___ \\ / _ \\  ");
    centerText("|  _ <  ___) / ___ \\ ");
    centerText("|_| \\_\\|____/_/   \\_\\");
    centerText("  ENCRYPTION SYSTEM  ");
    resetColor();
}

void displayExamBanner() {
    setColor(COLOR_INFO);
    centerText("");
    centerText(" _____ __  __    _    __  __ ");
    centerText("| ____|  \\/  |  / \\  |  \\/  |");
    centerText("|  _|  | |\\/| | / _ \\ | |\\/| |");
    centerText("| |___ | |  | |/ ___ \\| |  | |");
    centerText("|_____|_|  |_/_/   \\_\\_|  |_|");
    centerText("      MANAGEMENT             ");
    resetColor();
}

void displayClassBanner() {
    setColor(COLOR_BORDER);
    centerText("");
    centerText("  ____ _        _    ____ ____  ");
    centerText(" / ___| |      / \\  / ___/ ___| ");
    centerText("| |   | |     / _ \\ \\___ \\___ \\ ");
    centerText("| |___| |___ / ___ \\ ___) |__) |");
    centerText(" \\____|_____/_/   \\_\\____/____/ ");
    centerText("      MANAGEMENT                ");
    resetColor();
}

void displayMessageBanner() {
    setColor(COLOR_SUCCESS);
    centerText("");
    centerText(" __  __ ____  ____   ____    _    ____ _____ ");
    centerText("|  \\/  | ___]/ ___] / ___|  / \\  / ___| ____|");
    centerText("| |\\/| | _|  \\___ \\| \\___ / _ \\| |  _|  _|  ");
    centerText("| |  | | |___ ___) | ___) / ___ \\ |_| | |___ ");
    centerText("|_|  |_|_____|____/|____/_/   \\_\\____|_____|");
    centerText("     SECURE MESSAGING                       ");
    resetColor();
}

//  RSA UTILITY FUNCTIONS 
bool isPrime(long long n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (long long i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

long long generatePrime(long long min, long long max) {
    long long prime;
    do {
        prime = min + rand() % (max - min + 1);
    } while (!isPrime(prime));
    return prime;
}

long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Extended Euclidean Algorithm - Educational display available
long long extendedGCD(long long a, long long b, long long& x, long long& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    long long x1, y1;
    long long gcd = extendedGCD(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return gcd;
}

long long modInverse(long long e, long long phi) {
    long long m0 = phi, t, q;
    long long x0 = 0, x1 = 1;
    if (phi == 1) return 0;
    while (e > 1) {
        q = e / phi;
        t = phi;
        phi = e % phi;
        e = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

long long modPow(long long base, long long exp, long long mod) {
    long long result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

void generateRSAKeys(RSAKeys& keys) {
    keys.p = generatePrime(100, 500);
    keys.q = generatePrime(100, 500);
    while (keys.q == keys.p) keys.q = generatePrime(100, 500);
    keys.n = keys.p * keys.q;
    keys.phi = (keys.p - 1) * (keys.q - 1);
    keys.e = 3;
    while (gcd(keys.e, keys.phi) != 1) keys.e += 2;
    keys.d = modInverse(keys.e, keys.phi);
}

void encryptMessage(const char* plaintext, char* ciphertext, long long e, long long n) {
    ciphertext[0] = '\0';
    char temp[20];
    int len = strlen(plaintext);
    for (int i = 0; i < len; i++) {
        long long m = (long long)(unsigned char)plaintext[i];
        long long c = modPow(m, e, n);
        sprintf(temp, "%lld ", c);
        strcat(ciphertext, temp);
    }
}

void decryptMessage(const char* ciphertext, char* plaintext, long long d, long long n) {
    plaintext[0] = '\0';
    char temp[5000];
    strncpy(temp, ciphertext, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    char* token = strtok(temp, " ");
    int idx = 0;
    while (token != NULL) {
        long long c = atoll(token);
        long long m = modPow(c, d, n);
        plaintext[idx++] = (char)m;
        token = strtok(NULL, " ");
    }
    plaintext[idx] = '\0';
}

//  NEW RSA FEATURES 
// Digital Signature using RSA
long long createSignature(const char* message, long long d, long long n) {
    long long hash = 0;
    int len = strlen(message);
    for (int i = 0; i < len; i++) {
        hash = (hash * 31 + message[i]) % 1000000007;
    }
    // Sign hash with private key
    return modPow(hash % n, d, n);
}

bool verifySignature(const char* message, long long signature, long long e, long long n) {
    long long hash = 0;
    int len = strlen(message);
    for (int i = 0; i < len; i++) {
        hash = (hash * 31 + message[i]) % 1000000007;
    }
    // Verify with public key
    long long decryptedHash = modPow(signature, e, n);
    return (hash % n) == decryptedHash;
}

// Integrity hash for messages
long long calculateIntegrityHash(const char* content) {
    long long hash = 5381;
    int len = strlen(content);
    for (int i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + content[i];
    }
    return hash;
}

//  UTILITY FUNCTIONS 
void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void pauseScreen() {
    cout << endl;
    drawBoxTop(40);
    drawBoxLine("Press Enter to continue...", 40, COLOR_INFO);
    drawBoxBottom(40);
    cin.get();
}

void displayHeader(const char* title) {
    clearScreen();
    int consoleWidth, dummyHeight;
    getConsoleDimensions(consoleWidth, dummyHeight);
    
    cout << endl;
    drawBoxTop(BOX_WIDTH);
    drawBoxLine(title, BOX_WIDTH, COLOR_HEADER);
    drawBoxBottom(BOX_WIDTH);
    cout << endl;
}

void displaySectionHeader(const char* title) {
    cout << endl;
    setColor(COLOR_BORDER);
    drawHorizontalLine('<', '=', '>', BOX_WIDTH);
    resetColor();
    setColor(COLOR_INFO);
    centerText(title);
    resetColor();
    setColor(COLOR_BORDER);
    drawHorizontalLine('<', '=', '>', BOX_WIDTH);
    resetColor();
    cout << endl;
}

long long hashPassword(const char* password) {
    long long hash = 0;
    int len = strlen(password);
    for (int i = 0; i < len; i++) {
        hash = (hash * 31 + password[i]) % 1000000007;
    }
    return hash;
}

void generateId(char* id, const char* prefix) {
    sprintf(id, "%s%d", prefix, idCounter++);
}

void generateClassCode(char* code) {
    for (int i = 0; i < 6; i++) {
        code[i] = '0' + (rand() % 10);
    }
    code[6] = '\0';
}

int findUser(const char* username) {
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

int findClass(const char* classId) {
    for (int i = 0; i < classCount; i++) {
        if (strcmp(classes[i].classId, classId) == 0) {
            return i;
        }
    }
    return -1;
}

int findExam(const char* examId) {
    for (int i = 0; i < examCount; i++) {
        if (strcmp(exams[i].id, examId) == 0) {
            return i;
        }
    }
    return -1;
}

bool isStudentInClass(const char* studentName, const char* classId) {
    int classIdx = findClass(classId);
    if (classIdx == -1) return false;
    for (int i = 0; i < classes[classIdx].studentCount; i++) {
        if (strcmp(classes[classIdx].enrolledStudents[i], studentName) == 0) {
            return true;
        }
    }
    return false;
}

int countPendingRequests() {
    int count = 0;
    for (int i = 0; i < requestCount; i++) {
        if (strcmp(requests[i].teacherName, currentUser) == 0 &&
            strcmp(requests[i].status, "pending") == 0) {
            count++;
        }
    }
    return count;
}

int countUnreadKeys() {
    int count = 0;
    for (int i = 0; i < keyDistCount; i++) {
        bool forMe = (strcmp(keyDist[i].toStudent, currentUser) == 0) ||
                     (keyDist[i].isClassWide && isStudentInClass(currentUser, keyDist[i].classId));
        if (forMe && !keyDist[i].isRead) {
            count++;
        }
    }
    return count;
}

//FILE HANDLING 
void saveUsers() {
    ofstream file("users.txt");
    if (!file.is_open()) return;
    file << userCount << "\n";
    for (int i = 0; i < userCount; i++) {
        file << users[i].username << ","
             << users[i].password << ","
             << users[i].role << ","
             << users[i].keys.n << ","
             << users[i].keys.e << ","
             << users[i].keys.d << ","
             << users[i].keys.p << ","
             << users[i].keys.q << ","
             << users[i].keys.phi << ","
             << users[i].isActive << "\n";
    }
    file.close();
}

void loadUsers() {
    ifstream file("users.txt");
    if (!file.is_open()) return;
    file >> userCount;
    file.ignore();
    for (int i = 0; i < userCount; i++) {
        char line[1000];
        file.getline(line, 1000);
        char* token = strtok(line, ",");
        if (token) strncpy(users[i].username, token, 49); users[i].username[49] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(users[i].password, token, 49); users[i].password[49] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(users[i].role, token, 19); users[i].role[19] = '\0';
        token = strtok(NULL, ",");
        if (token) users[i].keys.n = atoll(token);
        token = strtok(NULL, ",");
        if (token) users[i].keys.e = atoll(token);
        token = strtok(NULL, ",");
        if (token) users[i].keys.d = atoll(token);
        token = strtok(NULL, ",");
        if (token) users[i].keys.p = atoll(token);
        token = strtok(NULL, ",");
        if (token) users[i].keys.q = atoll(token);
        token = strtok(NULL, ",");
        if (token) users[i].keys.phi = atoll(token);
        token = strtok(NULL, ",");
        if (token) users[i].isActive = atoi(token);
    }
    file.close();
}

void saveClasses() {
    ofstream file("classes.txt");
    if (!file.is_open()) return;
    file << classCount << "\n";
    for (int i = 0; i < classCount; i++) {
        file << classes[i].classId << ","
             << classes[i].className << ","
             << classes[i].classCode << ","
             << classes[i].teacherName << ","
             << classes[i].studentCount << ",";
        if (classes[i].studentCount == 0) {
            file << "NONE";
        } else {
            for (int j = 0; j < classes[i].studentCount; j++) {
                file << classes[i].enrolledStudents[j];
                if (j < classes[i].studentCount - 1) file << ";";
            }
        }
        file << "," << classes[i].examCount << ",";
        if (classes[i].examCount == 0) {
            file << "NONE";
        } else {
            for (int j = 0; j < classes[i].examCount; j++) {
                file << classes[i].assignedExams[j];
                if (j < classes[i].examCount - 1) file << ";";
            }
        }
        file << "," << classes[i].isActive << "\n";
    }
    file.close();
}

void loadClasses() {
    ifstream file("classes.txt");
    if (!file.is_open()) {
        classCount = 0;
        return;
    }
    int fileHeaderCount;
    file >> fileHeaderCount;
    file.ignore();
    classCount = 0;
    char line[2000];
    while (file.getline(line, 2000) && classCount < MAX_CLASSES) {
        char* cols[20];
        int colIdx = 0;
        char* ptr = strtok(line, ",");
        while (ptr != NULL && colIdx < 20) {
            cols[colIdx++] = ptr;
            ptr = strtok(NULL, ",");
        }
        if (colIdx < 8) continue;
        strncpy(classes[classCount].classId, cols[0], 19); classes[classCount].classId[19] = '\0';
        strncpy(classes[classCount].className, cols[1], 99); classes[classCount].className[99] = '\0';
        strncpy(classes[classCount].classCode, cols[2], 9); classes[classCount].classCode[9] = '\0';
        strncpy(classes[classCount].teacherName, cols[3], 49); classes[classCount].teacherName[49] = '\0';
        classes[classCount].studentCount = atoi(cols[4]);
        if (strcmp(cols[5], "NONE") != 0) {
            char tempStudents[1000];
            strncpy(tempStudents, cols[5], 999); tempStudents[999] = '\0';
            char* student = strtok(tempStudents, ";");
            int j = 0;
            while (student != NULL && j < classes[classCount].studentCount) {
                strncpy(classes[classCount].enrolledStudents[j++], student, 49);
                classes[classCount].enrolledStudents[j-1][49] = '\0';
                student = strtok(NULL, ";");
            }
        }
        classes[classCount].examCount = atoi(cols[6]);
        if (strcmp(cols[7], "NONE") != 0) {
            char tempExams[1000];
            strncpy(tempExams, cols[7], 999); tempExams[999] = '\0';
            char* exam = strtok(tempExams, ";");
            int j = 0;
            while (exam != NULL && j < classes[classCount].examCount) {
                strncpy(classes[classCount].assignedExams[j++], exam, 19);
                classes[classCount].assignedExams[j-1][19] = '\0';
                exam = strtok(NULL, ";");
            }
        }
        classes[classCount].isActive = atoi(cols[8]);
        classCount++;
    }
    file.close();
}

void saveExams() {
    ofstream file("exams.txt");
    if (!file.is_open()) return;
    file << examCount << "\n";
    for (int i = 0; i < examCount; i++) {
        file << exams[i].id << ","
             << exams[i].title << ","
             << exams[i].encryptedContent << ","
             << exams[i].teacherName << ","
             << exams[i].assignedClassId << ","
             << exams[i].assignedClassName << ","
             << exams[i].duration << ","
             << exams[i].isActive << ","
             << exams[i].approvedCount << ",";
        if (exams[i].approvedCount == 0) {
            file << "NONE";
        } else {
            for (int j = 0; j < exams[i].approvedCount; j++) {
                file << exams[i].approvedStudents[j];
                if (j < exams[i].approvedCount - 1) file << ";";
            }
        }
        file << "," << exams[i].keyDistributed << ","
             << exams[i].signature.signedBy << ","
             << exams[i].signature.signatureHash << ","
             << exams[i].signature.isVerified << ","
             << exams[i].exam_n << ","
             << exams[i].exam_e << ","
             << exams[i].exam_d << ","
             << exams[i].exam_p << ","
             << exams[i].exam_q << "\n";
    }
    file.close();
}

void loadExams() {
    ifstream file("exams.txt");
    if (!file.is_open()) return;
    file >> examCount;
    file.ignore();
    for (int i = 0; i < examCount; i++) {
        char line[6000];
        file.getline(line, 6000);
        char* cols[30];
        int colIdx = 0;
        char* ptr = strtok(line, ",");
        while (ptr != NULL && colIdx < 20) {
            cols[colIdx++] = ptr;
            ptr = strtok(NULL, ",");
        }
        if (colIdx < 10) continue;
        strncpy(exams[i].id, cols[0], 19); exams[i].id[19] = '\0';
        strncpy(exams[i].title, cols[1], 99); exams[i].title[99] = '\0';
        strncpy(exams[i].encryptedContent, cols[2], 4999); exams[i].encryptedContent[4999] = '\0';
        strncpy(exams[i].teacherName, cols[3], 49); exams[i].teacherName[49] = '\0';
        strncpy(exams[i].assignedClassId, cols[4], 19); exams[i].assignedClassId[19] = '\0';
        strncpy(exams[i].assignedClassName, cols[5], 99); exams[i].assignedClassName[99] = '\0';
        exams[i].duration = atoi(cols[6]);
        exams[i].isActive = atoi(cols[7]);
        exams[i].approvedCount = atoi(cols[8]);
        if (strcmp(cols[9], "NONE") != 0) {
            char tempStudents[1000];
            strncpy(tempStudents, cols[9], 999); tempStudents[999] = '\0';
            char* student = strtok(tempStudents, ";");
            int j = 0;
            while (student != NULL && j < exams[i].approvedCount) {
                strncpy(exams[i].approvedStudents[j++], student, 49);
                exams[i].approvedStudents[j-1][49] = '\0';
                student = strtok(NULL, ";");
            }
        }
        exams[i].keyDistributed = atoi(cols[10]);
        if (colIdx > 13) {
            strncpy(exams[i].signature.signedBy, cols[11], 49);
            exams[i].signature.signatureHash = atoll(cols[12]);
            exams[i].signature.isVerified = atoi(cols[13]);
            ptr = strtok(NULL, ","); if(ptr) exams[i].exam_n = atoll(ptr);
        ptr = strtok(NULL, ","); if(ptr) exams[i].exam_e = atoll(ptr);
        ptr = strtok(NULL, ","); if(ptr) exams[i].exam_d = atoll(ptr);
        ptr = strtok(NULL, ","); if(ptr) exams[i].exam_p = atoll(ptr);
        ptr = strtok(NULL, ","); if(ptr) exams[i].exam_q = atoll(ptr);
        }
    }
    file.close();
}

void saveAssignments() {
    ofstream file("assignments.txt");
    if (!file.is_open()) return;
    file << assignmentCount << "\n";
    for (int i = 0; i < assignmentCount; i++) {
        file << assignments[i].id << ","
             << assignments[i].studentName << ","
             << assignments[i].courseName << ","
             << assignments[i].encryptedSubmission << ","
             << assignments[i].encryptedGrade << ","
             << assignments[i].isGraded << ","
             << assignments[i].signature.signedBy << ","
             << assignments[i].signature.signatureHash << ","
             << assignments[i].signature.isVerified << "\n";
    }
    file.close();
}

void loadAssignments() {
    ifstream file("assignments.txt");
    if (!file.is_open()) return;
    file >> assignmentCount;
    file.ignore();
    for (int i = 0; i < assignmentCount; i++) {
        char line[7000];
        file.getline(line, 7000);
        char* token = strtok(line, ",");
        if (token) strncpy(assignments[i].id, token, 19); assignments[i].id[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(assignments[i].studentName, token, 49); assignments[i].studentName[49] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(assignments[i].courseName, token, 99); assignments[i].courseName[99] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(assignments[i].encryptedSubmission, token, 4999); assignments[i].encryptedSubmission[4999] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(assignments[i].encryptedGrade, token, 999); assignments[i].encryptedGrade[999] = '\0';
        token = strtok(NULL, ",");
        if (token) assignments[i].isGraded = atoi(token);
        token = strtok(NULL, ",");
        if (token) strncpy(assignments[i].signature.signedBy, token, 49);
        token = strtok(NULL, ",");
        if (token) assignments[i].signature.signatureHash = atoll(token);
        token = strtok(NULL, ",");
        if (token) assignments[i].signature.isVerified = atoi(token);
    }
    file.close();
}

void savemessagesList() {
    ofstream file("messagesList.txt");
    if (!file.is_open()) return;
    file << messageCount << "\n";
    for (int i = 0; i < messageCount; i++) {
        file << messagesList[i].id << ","
             << messagesList[i].from << ","
             << messagesList[i].to << ","
             << messagesList[i].encryptedContent << ","
             << messagesList[i].isRead << ","
             << messagesList[i].integrityHash << "\n";
    }
    file.close();
}

void loadmessagesList() {
    ifstream file("messagesList.txt");
    if (!file.is_open()) return;
    file >> messageCount;
    file.ignore();
    for (int i = 0; i < messageCount; i++) {
        char line[3000];
        file.getline(line, 3000);
        char* token = strtok(line, ",");
        if (token) strncpy(messagesList[i].id, token, 19); messagesList[i].id[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(messagesList[i].from, token, 49); messagesList[i].from[49] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(messagesList[i].to, token, 49); messagesList[i].to[49] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(messagesList[i].encryptedContent, token, 1999); messagesList[i].encryptedContent[1999] = '\0';
        token = strtok(NULL, ",");
        if (token) messagesList[i].isRead = atoi(token);
        token = strtok(NULL, ",");
        if (token) messagesList[i].integrityHash = atoll(token);
    }
    file.close();
}

void saveRequests() {
    ofstream file("requests.txt");
    if (!file.is_open()) return;
    file << requestCount << "\n";
    for (int i = 0; i < requestCount; i++) {
        file << requests[i].id << ","
             << requests[i].studentName << ","
             << requests[i].examId << ","
             << requests[i].examTitle << ","
             << requests[i].teacherName << ","
             << requests[i].classId << ","
             << requests[i].status << ","
             << requests[i].message << "\n";
    }
    file.close();
}

void loadRequests() {
    ifstream file("requests.txt");
    if (!file.is_open()) return;
    file >> requestCount;
    file.ignore();
    for (int i = 0; i < requestCount; i++) {
        char line[1000];
        file.getline(line, 1000);
        char* token = strtok(line, ",");
        if (token) strncpy(requests[i].id, token, 19); requests[i].id[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(requests[i].studentName, token, 49); requests[i].studentName[49] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(requests[i].examId, token, 19); requests[i].examId[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(requests[i].examTitle, token, 99); requests[i].examTitle[99] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(requests[i].teacherName, token, 49); requests[i].teacherName[49] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(requests[i].classId, token, 19); requests[i].classId[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(requests[i].status, token, 19); requests[i].status[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(requests[i].message, token, 499); requests[i].message[499] = '\0';
    }
    file.close();
}

void saveKeyDistributions() {
    ofstream file("keydist.txt");
    if (!file.is_open()) return;
    file << keyDistCount << "\n";
    for (int i = 0; i < keyDistCount; i++) {
        file << keyDist[i].id << ","
             << keyDist[i].examId << ","
             << keyDist[i].examTitle << ","
             << keyDist[i].classId << ","
             << keyDist[i].className << ","
             << keyDist[i].fromTeacher << ","
             << keyDist[i].toStudent << ","
             << keyDist[i].publicKeyE << ","
             << keyDist[i].publicKeyN << ","
             << keyDist[i].p << ","
             << keyDist[i].q << ","
             << keyDist[i].isClassWide << ","
             << keyDist[i].isRead << "\n";
    }
    file.close();
}

void loadKeyDistributions() {
    ifstream file("keydist.txt");
    if (!file.is_open()) return;
    file >> keyDistCount;
    file.ignore();
    for (int i = 0; i < keyDistCount; i++) {
        char line[1000];
        file.getline(line, 1000);
        char* token = strtok(line, ",");
        if (token) strncpy(keyDist[i].id, token, 19); keyDist[i].id[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(keyDist[i].examId, token, 19); keyDist[i].examId[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(keyDist[i].examTitle, token, 99); keyDist[i].examTitle[99] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(keyDist[i].classId, token, 19); keyDist[i].classId[19] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(keyDist[i].className, token, 99); keyDist[i].className[99] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(keyDist[i].fromTeacher, token, 49); keyDist[i].fromTeacher[49] = '\0';
        token = strtok(NULL, ",");
        if (token) strncpy(keyDist[i].toStudent, token, 49); keyDist[i].toStudent[49] = '\0';
        token = strtok(NULL, ",");
        if (token) keyDist[i].publicKeyE = atoll(token);
        token = strtok(NULL, ",");
        if (token) keyDist[i].publicKeyN = atoll(token);
        token = strtok(NULL, ","); if (token) keyDist[i].p = atoll(token);
        token = strtok(NULL, ","); if (token) keyDist[i].q = atoll(token);
        token = strtok(NULL, ",");
        if (token) keyDist[i].isClassWide = atoi(token);
        token = strtok(NULL, ",");
        if (token) keyDist[i].isRead = atoi(token);
    }
    file.close();
}

void loadAllData() {
    loadUsers();
    loadClasses();
    loadExams();
    loadAssignments();
    loadmessagesList();
    loadRequests();
    loadKeyDistributions();
}

void saveAllData() {
    saveUsers();
    saveClasses();
    saveExams();
    saveAssignments();
    savemessagesList();
    saveRequests();
    saveKeyDistributions();
}

// NEW FEATURE: VIEW RSA KEY INFO 
void viewMyKeyInfo() {
    clearScreen();
    displayRSABanner();
    displayHeader("MY RSA KEY INFORMATION");
    
    int userIdx = findUser(currentUser);
    if (userIdx == -1) {
        drawBoxTop();
        drawBoxLine("Error: User not found!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    RSAKeys& keys = users[userIdx].keys;
    
    drawBoxTop();
    drawBoxLine("=== YOUR RSA KEYS ===", BOX_WIDTH, COLOR_HEADER);
    drawBoxMiddle();
    
    char buffer[100];
    
    drawBoxLineLeft("PUBLIC KEY (Share this):", BOX_WIDTH, COLOR_SUCCESS);
    sprintf(buffer, "  e = %lld", keys.e);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
    sprintf(buffer, "  n = %lld", keys.n);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
    
    drawBoxMiddle();
    
    drawBoxLineLeft("PRIVATE KEY (Keep secret!):", BOX_WIDTH, COLOR_ERROR);
    sprintf(buffer, "  d = %lld", keys.d);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
    
    drawBoxMiddle();
    
    drawBoxLineLeft("KEY GENERATION PARAMETERS:", BOX_WIDTH, COLOR_HEADER);
    sprintf(buffer, "  Prime p = %lld", keys.p);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
    sprintf(buffer, "  Prime q = %lld", keys.q);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
    sprintf(buffer, "  phi(n) = %lld", keys.phi);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
    sprintf(buffer, "  n = p * q = %lld", keys.n);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
    
    drawBoxMiddle();
    
    // Verify key correctness
    bool valid = (keys.n == keys.p * keys.q) && 
                 (keys.phi == (keys.p - 1) * (keys.q - 1)) &&
                 (gcd(keys.e, keys.phi) == 1) &&
                 ((keys.e * keys.d) % keys.phi == 1);
    
    if (valid) {
        drawBoxLine("KEY VERIFICATION: VALID", BOX_WIDTH, COLOR_SUCCESS);
    } else {
        drawBoxLine("KEY VERIFICATION: INVALID", BOX_WIDTH, COLOR_ERROR);
    }
    
    drawBoxBottom();
    
    cout << endl;
    drawBoxTop(50);
    drawBoxLine("RSA FORMULA REFERENCE", 50, COLOR_HEADER);
    drawBoxMiddle(50);
    drawBoxLineLeft("Encrypt: C = M^e mod n", 50, COLOR_INFO);
    drawBoxLineLeft("Decrypt: M = C^d mod n", 50, COLOR_INFO);
    drawBoxLineLeft("Sign:    S = H^d mod n", 50, COLOR_INFO);
    drawBoxLineLeft("Verify:  H = S^e mod n", 50, COLOR_INFO);
    drawBoxBottom(50);
    
    pauseScreen();
}

//NEW FEATURE: RSA ENCRYPTION DEMO 
void rsaEncryptionDemo() {
    clearScreen();
    displayRSABanner();
    displayHeader("RSA ENCRYPTION DEMO");
    
    int userIdx = findUser(currentUser);
    RSAKeys& keys = users[userIdx].keys;
    
    drawBoxTop();
    drawBoxLine("Interactive RSA Demonstration", BOX_WIDTH, COLOR_HEADER);
    drawBoxBottom();
    
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Enter a message to encrypt (max 50 chars): ";
    resetColor();
    
    char message[51];
    cin.getline(message, 51);
    
    if (strlen(message) == 0) {
        drawBoxTop();
        drawBoxLine("No message entered!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    cout << endl;
    displaySectionHeader("STEP 1: ORIGINAL MESSAGE");
    drawBoxTop();
    drawBoxLine(message, BOX_WIDTH, COLOR_SUCCESS);
    drawBoxBottom();
    
    // Show character-by-character encryption
    displaySectionHeader("STEP 2: CHARACTER ENCRYPTION");
    
    const char* headers[] = {"Char", "ASCII", "Encrypted"};
    int colWidths[] = {8, 12, 20};
    int totalWidth = 44;
    
    drawTableHeader(headers, 3, colWidths, totalWidth);
    
    char encrypted[2000];
    encrypted[0] = '\0';
    char temp[20];
    
    int len = strlen(message);
    for (int i = 0; i < len && i < 10; i++) {  // Show first 10 chars
        long long m = (long long)(unsigned char)message[i];
        long long c = modPow(m, keys.e, keys.n);
        
        char charStr[10], asciiStr[15], encStr[25];
        sprintf(charStr, "%c", message[i]);
        sprintf(asciiStr, "%lld", m);
        sprintf(encStr, "%lld", c);
        
        const char* row[] = {charStr, asciiStr, encStr};
        drawTableRow(row, 3, colWidths, totalWidth);
        
        sprintf(temp, "%lld ", c);
        strcat(encrypted, temp);
    }
    
    if (len > 10) {
        const char* ellipsis[] = {"...", "...", "..."};
        drawTableRow(ellipsis, 3, colWidths, totalWidth);
    }
    
    drawTableBottom(3, colWidths, totalWidth);
    
    // Full encryption
    encryptMessage(message, encrypted, keys.e, keys.n);
    
    displaySectionHeader("STEP 3: ENCRYPTED MESSAGE");
    cout << endl;
    setColor(COLOR_BOX);
    centerText("+----------------------------------------------------------+");
    resetColor();
    setColor(COLOR_ERROR);
    // Print encrypted in chunks
    int eLen = strlen(encrypted);
    for (int i = 0; i < eLen; i += 50) {
        char chunk[51];
        strncpy(chunk, encrypted + i, 50);
        chunk[50] = '\0';
        centerText(chunk);
    }
    resetColor();
    setColor(COLOR_BOX);
    centerText("+----------------------------------------------------------+");
    resetColor();
    
    // Decryption
    displaySectionHeader("STEP 4: DECRYPTION");
    char decrypted[2000];
    decryptMessage(encrypted, decrypted, keys.d, keys.n);
    
    drawBoxTop();
    drawBoxLine("Decrypted Message:", BOX_WIDTH, COLOR_HEADER);
    drawBoxLine(decrypted, BOX_WIDTH, COLOR_SUCCESS);
    drawBoxBottom();
    
    // Verify
    cout << endl;
    if (strcmp(message, decrypted) == 0) {
        drawBoxTop(40);
        drawBoxLine("VERIFICATION: SUCCESS!", 40, COLOR_SUCCESS);
        drawBoxLine("Original = Decrypted", 40, COLOR_SUCCESS);
        drawBoxBottom(40);
    } else {
        drawBoxTop(40);
        drawBoxLine("VERIFICATION: FAILED!", 40, COLOR_ERROR);
        drawBoxBottom(40);
    }
    
    pauseScreen();
}

//  NEW FEATURE: DIGITAL SIGNATURE DEMO
void digitalSignatureDemo() {
    clearScreen();
    displayRSABanner();
    displayHeader("DIGITAL SIGNATURE DEMO");
    
    int userIdx = findUser(currentUser);
    RSAKeys& keys = users[userIdx].keys;
    
    drawBoxTop();
    drawBoxLine("Digital Signature Demonstration", BOX_WIDTH, COLOR_HEADER);
    drawBoxMiddle();
    drawBoxLineLeft("Sign with PRIVATE key (d)", BOX_WIDTH, COLOR_INFO);
    drawBoxLineLeft("Verify with PUBLIC key (e)", BOX_WIDTH, COLOR_INFO);
    drawBoxBottom();
    
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Enter a document to sign: ";
    resetColor();
    
    char document[200];
    cin.getline(document, 200);
    
    if (strlen(document) == 0) {
        strcpy(document, "This is a test document");
    }
    
    displaySectionHeader("STEP 1: ORIGINAL DOCUMENT");
    drawBoxTop();
    drawBoxLine(document, BOX_WIDTH, COLOR_SUCCESS);
    drawBoxBottom();
    
    // Create hash
    displaySectionHeader("STEP 2: CALCULATE HASH");
    long long hash = 0;
    int len = strlen(document);
    for (int i = 0; i < len; i++) {
        hash = (hash * 31 + document[i]) % 1000000007;
    }
    
    char buffer[100];
    sprintf(buffer, "Hash(document) = %lld", hash);
    drawBoxTop();
    drawBoxLine(buffer, BOX_WIDTH, COLOR_INFO);
    drawBoxBottom();
    
    // Sign
    displaySectionHeader("STEP 3: CREATE SIGNATURE");
    long long signature = createSignature(document, keys.d, keys.n);
    
    sprintf(buffer, "Signature = Hash^d mod n");
    drawBoxTop();
    drawBoxLine(buffer, BOX_WIDTH, COLOR_HEADER);
    sprintf(buffer, "Signature = %lld", signature);
    drawBoxLine(buffer, BOX_WIDTH, COLOR_SUCCESS);
    drawBoxBottom();
    
    // Verify
    displaySectionHeader("STEP 4: VERIFY SIGNATURE");
    bool verified = verifySignature(document, signature, keys.e, keys.n);
    
    drawBoxTop();
    drawBoxLine("Verification: Signature^e mod n = Hash?", BOX_WIDTH, COLOR_HEADER);
    if (verified) {
        drawBoxLine("SIGNATURE VALID!", BOX_WIDTH, COLOR_SUCCESS);
    } else {
        drawBoxLine("SIGNATURE INVALID!", BOX_WIDTH, COLOR_ERROR);
    }
    drawBoxBottom();
    
    // Tamper test
    cout << endl;
    drawBoxTop(50);
    drawBoxLine("TAMPER TEST", 50, COLOR_INFO);
    drawBoxMiddle(50);
    drawBoxLineLeft("Modified document:", 50, COLOR_DEFAULT);
    
    char tampered[200];
    strcpy(tampered, document);
    if (strlen(tampered) > 0) tampered[0] = tampered[0] + 1;
    
    bool tamperedVerify = verifySignature(tampered, signature, keys.e, keys.n);
    
    if (!tamperedVerify) {
        drawBoxLine("Tamper detected correctly!", 50, COLOR_SUCCESS);
    } else {
        drawBoxLine("Warning: Tamper not detected", 50, COLOR_ERROR);
    }
    drawBoxBottom(50);
    
    pauseScreen();
}

// USER REGISTRATION & LOGIN 
void  registerUser() {
    clearScreen();
    displayMainBanner();
    displayHeader("REGISTER NEW USER");
    
    if (userCount >= MAX_USERS) {
        drawBoxTop();
        drawBoxLine("[!] Maximum user limit reached!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    char username[50], role[20], password[50];
    
    drawBoxTop();
    drawBoxLine("Enter Registration Details", BOX_WIDTH, COLOR_HEADER);
    drawBoxBottom();
    
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Username: ";
    resetColor();
    cin.getline(username, 50);
    
    if (findUser(username) != -1) {
        drawBoxTop();
        drawBoxLine("[!] Username already exists!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    setColor(COLOR_INFO);
    cout << "                                                    Role (teacher/student): ";
    resetColor();
    cin.getline(role, 20);
    
    int len = strlen(role);
    for (int i = 0; i < len; i++) {
        if (role[i] >= 'A' && role[i] <= 'Z') role[i] += 32;
    }
    
    if (strcmp(role, "teacher") != 0 && strcmp(role, "student") != 0) {
        drawBoxTop();
        drawBoxLine("[!] Invalid role!", BOX_WIDTH, COLOR_ERROR);
        drawBoxLine("Must be 'teacher' or 'student'", BOX_WIDTH, COLOR_DEFAULT);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    setColor(COLOR_INFO);
    cout << "                                                    Password: ";
    resetColor();
    cin.getline(password, 50);
    
    if (strlen(password) < 4) {
        drawBoxTop();
        drawBoxLine("[!] Password too short!", BOX_WIDTH, COLOR_ERROR);
        drawBoxLine("Minimum 4 characters required", BOX_WIDTH, COLOR_DEFAULT);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    strncpy(users[userCount].username, username, 49); 
    users[userCount].username[49] = '\0';
    sprintf(users[userCount].password, "%lld", hashPassword(password));
    strncpy(users[userCount].role, role, 19); 
    users[userCount].role[19] = '\0';
    generateRSAKeys(users[userCount].keys);
    users[userCount].isActive = true;
    
    cout << endl;
    drawBoxTop();
    drawBoxLine("REGISTRATION SUCCESSFUL!", BOX_WIDTH, COLOR_SUCCESS);
    drawBoxMiddle();
    
    char buffer[100];
    sprintf(buffer, "Username: %s", username);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
    sprintf(buffer, "Role: %s", role);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
    
    drawBoxMiddle();
    drawBoxLine("RSA KEYS GENERATED", BOX_WIDTH, COLOR_HEADER);
    drawBoxMiddle();
    
    sprintf(buffer, "Public Key (e): %lld", users[userCount].keys.e);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_SUCCESS);
    sprintf(buffer, "Public Key (n): %lld", users[userCount].keys.n);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_SUCCESS);
    sprintf(buffer, "Private Key (d): %lld [KEEP SECRET]", users[userCount].keys.d);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_ERROR);
    
    drawBoxBottom();
    
    userCount++;
    saveUsers();
    pauseScreen();
}

bool login() {
    clearScreen();
    displayMainBanner();
    displayHeader("USER LOGIN");
    
    char username[50], password[50], attemptedRole[20];
    
    drawBoxTop();
    drawBoxLine("Enter Login Credentials", BOX_WIDTH, COLOR_HEADER);
    drawBoxBottom();
    
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Username: ";
    resetColor();
    cin.getline(username, 50);
    
    setColor(COLOR_INFO);
    cout << "                                                    Password: ";
    resetColor();
    cin.getline(password, 50);
    
    setColor(COLOR_INFO);
    cout << "                                                    Login as (teacher/student): ";
    resetColor();
    cin.getline(attemptedRole, 20);
    
    int len = strlen(attemptedRole);
    for (int i = 0; i < len; i++) {
        if (attemptedRole[i] >= 'A' && attemptedRole[i] <= 'Z') attemptedRole[i] += 32;
    }
    
    int userIdx = findUser(username);
    if (userIdx == -1) {
        cout << endl;
        drawBoxTop();
        drawBoxLine("[!] User not found!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return false;
    }
    
    char hashedPass[50];
    sprintf(hashedPass, "%lld", hashPassword(password));
    
    if (strcmp(users[userIdx].password, hashedPass) != 0) {
        cout << endl;
        drawBoxTop();
        drawBoxLine("[!] Incorrect password!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return false;
    }
    
    if (strcmp(users[userIdx].role, attemptedRole) != 0) {
        cout << endl;
        drawBoxTop();
        drawBoxLine("ACCESS DENIED", BOX_WIDTH, COLOR_ERROR);
        drawBoxMiddle();
        char buffer[60];
        sprintf(buffer, "You are registered as: %s", users[userIdx].role);
        drawBoxLine(buffer, BOX_WIDTH, COLOR_INFO);
        sprintf(buffer, "Cannot login to: %s portal", attemptedRole);
        drawBoxLine(buffer, BOX_WIDTH, COLOR_INFO);
        drawBoxBottom();
        pauseScreen();
        return false;
    }
    
    if (!users[userIdx].isActive) {
        cout << endl;
        drawBoxTop();
        drawBoxLine("[!] Account is deactivated!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return false;
    }
    
    strncpy(currentUser, username, 49); 
    currentUser[49] = '\0';
    strncpy(currentRole, users[userIdx].role, 19); 
    currentRole[19] = '\0';
    
    cout << endl;
    drawBoxTop();
    drawBoxLine("LOGIN SUCCESSFUL!", BOX_WIDTH, COLOR_SUCCESS);
    drawBoxMiddle();
    
    char buffer[60];
    sprintf(buffer, "Welcome back, %s!", username);
    drawBoxLine(buffer, BOX_WIDTH, COLOR_INFO);
    sprintf(buffer, "Role: %s", currentRole);
    drawBoxLine(buffer, BOX_WIDTH, COLOR_DEFAULT);
    
    drawBoxBottom();
    
    // Notifications
    if (strcmp(currentRole, "teacher") == 0) {
        int pending = countPendingRequests();
        if (pending > 0) {
            cout << endl;
            drawBoxTop(50);
            char notif[60];
            sprintf(notif, "[!] %d pending access request(s)", pending);
            drawBoxLine(notif, 50, COLOR_INFO);
            drawBoxBottom(50);
        }
    } else {
        int unreadKeys = countUnreadKeys();
        if (unreadKeys > 0) {
            cout << endl;
            drawBoxTop(50);
            char notif[60];
            sprintf(notif, "[!] %d new exam key(s)", unreadKeys);
            drawBoxLine(notif, 50, COLOR_INFO);
            drawBoxBottom(50);
        }
    }
    
    pauseScreen();
    return true;
}

// CLASS MANAGEMENT 
void createClass() {
    clearScreen();
    displayClassBanner();
    displayHeader("CREATE NEW CLASS");
    
    if (classCount >= MAX_CLASSES) {
        drawBoxTop();
        drawBoxLine("[!] Maximum class limit reached!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    char className[100];
    
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Enter Class Name: ";
    resetColor();
    cin.getline(className, 100);
    
    if (strlen(className) == 0) {
        drawBoxTop();
        drawBoxLine("[!] Class name cannot be empty!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    generateId(classes[classCount].classId, "CLS");
    strncpy(classes[classCount].className, className, 99); 
    classes[classCount].className[99] = '\0';
    generateClassCode(classes[classCount].classCode);
    strncpy(classes[classCount].teacherName, currentUser, 49); 
    classes[classCount].teacherName[49] = '\0';
    classes[classCount].studentCount = 0;
    classes[classCount].examCount = 0;
    classes[classCount].isActive = true;
    
    cout << endl;
    drawBoxTop();
    drawBoxLine("CLASS CREATED SUCCESSFULLY!", BOX_WIDTH, COLOR_SUCCESS);
    drawBoxMiddle();
    
    char buffer[60];
    sprintf(buffer, "Class ID: %s", classes[classCount].classId);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
    sprintf(buffer, "Class Name: %s", className);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
    
    drawBoxMiddle();
    drawBoxLine("JOIN CODE", BOX_WIDTH, COLOR_HEADER);
    drawBoxMiddle();
    
    // Large display of join code
    char codeDisplay[20];
    sprintf(codeDisplay, "[ %s ]", classes[classCount].classCode);
    drawBoxLine(codeDisplay, BOX_WIDTH, COLOR_SUCCESS);
    
    drawBoxMiddle();
    drawBoxLine("Share this code with students!", BOX_WIDTH, COLOR_INFO);
    drawBoxBottom();
    
    classCount++;
    saveClasses();
    pauseScreen();
}

void viewMyClasses() {
    clearScreen();
    displayClassBanner();
    displayHeader("MY CLASSES");
    
    bool found = false;
    
    for (int i = 0; i < classCount; i++) {
        if (strcmp(classes[i].teacherName, currentUser) == 0 && classes[i].isActive) {
            found = true;
            cout << endl;
            drawBoxTop();
            
            char buffer[60];
            drawBoxLine(classes[i].className, BOX_WIDTH, COLOR_HEADER);
            drawBoxMiddle();
            
            sprintf(buffer, "ID: %s", classes[i].classId);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
            sprintf(buffer, "Join Code: %s", classes[i].classCode);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_SUCCESS);
            sprintf(buffer, "Students: %d", classes[i].studentCount);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
            sprintf(buffer, "Exams: %d", classes[i].examCount);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
            
            if (classes[i].studentCount > 0) {
                drawBoxMiddle();
                drawBoxLine("Enrolled Students:", BOX_WIDTH, COLOR_INFO);
                for (int j = 0; j < classes[i].studentCount; j++) {
                    sprintf(buffer, "  - %s", classes[i].enrolledStudents[j]);
                    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
                }
            }
            
            drawBoxBottom();
        }
    }
    
    if (!found) {
        cout << endl;
        drawBoxTop();
        drawBoxLine("No classes created yet", BOX_WIDTH, COLOR_INFO);
        drawBoxLine("Use 'Create Class' to get started!", BOX_WIDTH, COLOR_DEFAULT);
        drawBoxBottom();
    }
    
    pauseScreen();
}

void joinClass() {
    clearScreen();
    displayClassBanner();
    displayHeader("JOIN A CLASS");
    
    drawBoxTop();
    drawBoxLine("Enter 6-digit class code", BOX_WIDTH, COLOR_INFO);
    drawBoxBottom();
    
    char code[10];
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Class Code: ";
    resetColor();
    cin.getline(code, 10);
    
    for (int i = 0; i < classCount; i++) {
        if (strcmp(classes[i].classCode, code) == 0 && classes[i].isActive) {
            for (int j = 0; j < classes[i].studentCount; j++) {
                if (strcmp(classes[i].enrolledStudents[j], currentUser) == 0) {
                    cout << endl;
                    drawBoxTop();
                    drawBoxLine("[!] Already enrolled in this class!", BOX_WIDTH, COLOR_ERROR);
                    drawBoxBottom();
                    pauseScreen();
                    return;
                }
            }
            
            if (classes[i].studentCount >= 50) {
                cout << endl;
                drawBoxTop();
                drawBoxLine("[!] Class is full!", BOX_WIDTH, COLOR_ERROR);
                drawBoxBottom();
                pauseScreen();
                return;
            }
            
            strncpy(classes[i].enrolledStudents[classes[i].studentCount], currentUser, 49);
            classes[i].enrolledStudents[classes[i].studentCount][49] = '\0';
            classes[i].studentCount++;
            saveClasses();
            
            cout << endl;
            drawBoxTop();
            drawBoxLine("SUCCESSFULLY JOINED CLASS!", BOX_WIDTH, COLOR_SUCCESS);
            drawBoxMiddle();
            
            char buffer[60];
            sprintf(buffer, "Class: %s", classes[i].className);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
            sprintf(buffer, "Teacher: %s", classes[i].teacherName);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
            
            drawBoxMiddle();
            drawBoxLine("You will receive exam keys from this class", BOX_WIDTH, COLOR_INFO);
            drawBoxBottom();
            
            pauseScreen();
            return;
        }
    }
    
    cout << endl;
    drawBoxTop();
    drawBoxLine("[!] Invalid class code!", BOX_WIDTH, COLOR_ERROR);
    drawBoxBottom();
    pauseScreen();
}

void viewMyEnrolledClasses() {
    clearScreen();
    displayClassBanner();
    displayHeader("MY ENROLLED CLASSES");
    
    bool found = false;
    
    // Table setup
    const char* headers[] = {"Class Name", "Teacher", "Students", "Exams"};
    int colWidths[] = {20, 15, 10, 8};
    int totalWidth = 57;
    
    bool headerPrinted = false;
    
    for (int i = 0; i < classCount; i++) {
        for (int j = 0; j < classes[i].studentCount; j++) {
            if (strcmp(classes[i].enrolledStudents[j], currentUser) == 0) {
                if (!headerPrinted) {
                    cout << endl;
                    drawTableHeader(headers, 4, colWidths, totalWidth);
                    headerPrinted = true;
                }
                
                found = true;
                char studentStr[15], examStr[10];
                sprintf(studentStr, "%d", classes[i].studentCount);
                sprintf(examStr, "%d", classes[i].examCount);
                
                const char* row[] = {classes[i].className, classes[i].teacherName, studentStr, examStr};
                drawTableRow(row, 4, colWidths, totalWidth);
                break;
            }
        }
    }
    
    if (found) {
        drawTableBottom(4, colWidths, totalWidth);
    } else {
        cout << endl;
        drawBoxTop();
        drawBoxLine("Not enrolled in any classes", BOX_WIDTH, COLOR_INFO);
        drawBoxLine("Use 'Join Class' to enroll!", BOX_WIDTH, COLOR_DEFAULT);
        drawBoxBottom();
    }
    
    pauseScreen();
}

// ============= EXAM MANAGEMENT =============
void createExam() {
    clearScreen();
    displayExamBanner();
    displayHeader("CREATE NEW EXAM");
    
    if (examCount >= MAX_EXAMS) {
        drawBoxTop();
        drawBoxLine("[!] Maximum exam limit reached!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    displaySectionHeader("YOUR CLASSES");
    
    bool hasClasses = false;
    const char* headers[] = {"Class ID", "Class Name", "Students"};
    int colWidths[] = {12, 25, 10};
    int totalWidth = 51;
    
    bool headerPrinted = false;
    
    for (int i = 0; i < classCount; i++) {
        if (strcmp(classes[i].teacherName, currentUser) == 0 && classes[i].isActive) {
            if (!headerPrinted) {
                drawTableHeader(headers, 3, colWidths, totalWidth);
                headerPrinted = true;
            }
            hasClasses = true;
            char studentStr[10];
            sprintf(studentStr, "%d", classes[i].studentCount);
            const char* row[] = {classes[i].classId, classes[i].className, studentStr};
            drawTableRow(row, 3, colWidths, totalWidth);
        }
    }
    
    if (hasClasses) {
        drawTableBottom(3, colWidths, totalWidth);
    } else {
        drawBoxTop();
        drawBoxLine("[!] Create a class first!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    char classId[20];
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Enter Class ID: ";
    resetColor();
    cin.getline(classId, 20);
    
    int classIdx = findClass(classId);
    if (classIdx == -1 || strcmp(classes[classIdx].teacherName, currentUser) != 0) {
        drawBoxTop();
        drawBoxLine("[!] Class not found!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    char title[100];
    setColor(COLOR_INFO);
    cout << "                                                    Enter Exam Title: ";
    resetColor();
    cin.getline(title, 100);
    
    displaySectionHeader("EXAM CONTENT");
    setColor(COLOR_INFO);
    cout << "                                                    Type 'END' on a new line to finish:\n\n";
    resetColor();
    
    char content[2000];
    content[0] = '\0';
    char line[200];
    while (cin.getline(line, 200)) {
        if (strcmp(line, "END") == 0) break;
        strncat(content, line, 1999 - strlen(content));
        strncat(content, "\n", 1999 - strlen(content));
    }
    
    if (strlen(content) == 0) {
        drawBoxTop();
        drawBoxLine("[!] Content cannot be empty!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    int duration;
    setColor(COLOR_INFO);
    cout << "\n                                                    Duration (minutes): ";
    resetColor();
    cin >> duration;
    cin.ignore();
    
    if (duration <= 0) {
        drawBoxTop();
        drawBoxLine("[!] Duration must be positive!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    generateId(exams[examCount].id, "EXAM");
    strncpy(exams[examCount].title, title, 99); 
    exams[examCount].title[99] = '\0';
    strncpy(exams[examCount].teacherName, currentUser, 49); 
    exams[examCount].teacherName[49] = '\0';
    strncpy(exams[examCount].assignedClassId, classId, 19); 
    exams[examCount].assignedClassId[19] = '\0';
    strncpy(exams[examCount].assignedClassName, classes[classIdx].className, 99); 
    exams[examCount].assignedClassName[99] = '\0';
    exams[examCount].duration = duration;
    exams[examCount].isActive = true;
    exams[examCount].approvedCount = 0;
    exams[examCount].keyDistributed = false;
    RSAKeys examKeys;
    generateRSAKeys(examKeys); 

    // Store them in the exam struct
    exams[examCount].exam_n = examKeys.n;
    exams[examCount].exam_e = examKeys.e;
    exams[examCount].exam_d = examKeys.d;
    exams[examCount].exam_p = examKeys.p;
    exams[examCount].exam_q = examKeys.q;
    int userIdx = findUser(currentUser);
   encryptMessage(content, exams[examCount].encryptedContent, exams[examCount].exam_e, exams[examCount].exam_n);
    
    // Digital signature
   long long sig = createSignature(content, users[userIdx].keys.d, users[userIdx].keys.n);
    strncpy(exams[examCount].signature.signedBy, currentUser, 49);
    exams[examCount].signature.signatureHash = sig;
    exams[examCount].signature.isVerified = true;
    
    if (classes[classIdx].examCount < 20) {
        strncpy(classes[classIdx].assignedExams[classes[classIdx].examCount], exams[examCount].id, 19);
        classes[classIdx].assignedExams[classes[classIdx].examCount][19] = '\0';
        classes[classIdx].examCount++;
    }
    
    cout << endl;
    drawBoxTop();
    drawBoxLine("EXAM CREATED SUCCESSFULLY!", BOX_WIDTH, COLOR_SUCCESS);
    drawBoxMiddle();
    
    char buffer[60];
    sprintf(buffer, "Exam ID: %s", exams[examCount].id);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
    sprintf(buffer, "Title: %s", title);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
    sprintf(buffer, "Class: %s", classes[classIdx].className);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
    sprintf(buffer, "Duration: %d minutes", duration);
    drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
    
    drawBoxMiddle();
    drawBoxLine("Content encrypted with RSA", BOX_WIDTH, COLOR_SUCCESS);
    drawBoxLine("Digital signature applied", BOX_WIDTH, COLOR_SUCCESS);
    
    drawBoxMiddle();
    drawBoxLine("[!] Don't forget to distribute the key!", BOX_WIDTH, COLOR_INFO);
    drawBoxBottom();
    
    examCount++;
    saveExams();
    saveClasses();
    pauseScreen();
}

void viewMyExams() {
    clearScreen();
    displayExamBanner();
    displayHeader("MY EXAMS");
    
    bool found = false;
    
    const char* headers[] = {"ID", "Title", "Class", "Duration", "Key Sent", "Access"};
    int colWidths[] = {10, 18, 12, 10, 9, 8};
    int totalWidth = 71;
    
    bool headerPrinted = false;
    
    for (int i = 0; i < examCount; i++) {
        if (strcmp(exams[i].teacherName, currentUser) == 0) {
            if (!headerPrinted) {
                cout << endl;
                drawTableHeader(headers, 6, colWidths, totalWidth);
                headerPrinted = true;
            }
            
            found = true;
            char durStr[15], accessStr[10];
            sprintf(durStr, "%d min", exams[i].duration);
            sprintf(accessStr, "%d", exams[i].approvedCount);
            
            const char* row[] = {
                exams[i].id, 
                exams[i].title, 
                exams[i].assignedClassName,
                durStr,
                exams[i].keyDistributed ? "Yes" : "No",
                accessStr
            };
            drawTableRow(row, 6, colWidths, totalWidth);
        }
    }
    
    if (found) {
        drawTableBottom(6, colWidths, totalWidth);
    } else {
        cout << endl;
        drawBoxTop();
        drawBoxLine("No exams created yet", BOX_WIDTH, COLOR_INFO);
        drawBoxBottom();
    }
    
    pauseScreen();
}


void distributeExamKey() {
    clearScreen();
    displayRSABanner();
    displayHeader("DISTRIBUTE EXAM KEY");
    
    if (keyDistCount >= MAX_KEYS) {
        drawBoxTop();
        drawBoxLine("[!] Maximum key distribution limit!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    displaySectionHeader("YOUR EXAMS");
    
    bool hasExams = false;
    const char* headers[] = {"Exam ID", "Title", "Key Status"};
    int colWidths[] = {12, 25, 12};
    int totalWidth = 53;
    
    bool headerPrinted = false;
    
    for (int i = 0; i < examCount; i++) {
        if (strcmp(exams[i].teacherName, currentUser) == 0 && exams[i].isActive) {
            if (!headerPrinted) {
                drawTableHeader(headers, 3, colWidths, totalWidth);
                headerPrinted = true;
            }
            hasExams = true;
            const char* row[] = {
                exams[i].id,
                exams[i].title,
                exams[i].keyDistributed ? "Sent" : "Pending"
            };
            drawTableRow(row, 3, colWidths, totalWidth);
        }
    }
    
    if (hasExams) {
        drawTableBottom(3, colWidths, totalWidth);
    } else {
        drawBoxTop();
        drawBoxLine("[!] No exams to distribute keys for", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    char examId[20];
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Enter Exam ID: ";
    resetColor();
    cin.getline(examId, 20);
    
    int examIdx = findExam(examId);
    if (examIdx == -1 || strcmp(exams[examIdx].teacherName, currentUser) != 0) {
        drawBoxTop();
        drawBoxLine("[!] Exam not found!", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }
    
    cout << endl;
    drawBoxTop(40);
    drawBoxLine("Distribution Options", 40, COLOR_HEADER);
    drawBoxMiddle(40);
    drawBoxLineLeft("1. Send to ENTIRE CLASS", 40, COLOR_INFO);
    drawBoxLineLeft("2. Send to INDIVIDUAL", 40, COLOR_INFO);
    drawBoxLineLeft("0. Cancel", 40, COLOR_DEFAULT);
    drawBoxBottom(40);
    
    cout << endl;
    setColor(COLOR_INFO);
    cout << "                                                    Choice: ";
    resetColor();
    
    int choice;
    cin >> choice;
    cin.ignore();
    
    if (choice == 0) {
        pauseScreen();
        return;
    }
    
    int userIdx = findUser(currentUser);
    
    if (choice == 1) {
        generateId(keyDist[keyDistCount].id, "KEY");
        strncpy(keyDist[keyDistCount].examId, exams[examIdx].id, 19);
        keyDist[keyDistCount].examId[19] = '\0';
        strncpy(keyDist[keyDistCount].examTitle, exams[examIdx].title, 99);
        keyDist[keyDistCount].examTitle[99] = '\0';
        strncpy(keyDist[keyDistCount].classId, exams[examIdx].assignedClassId, 19);
        keyDist[keyDistCount].classId[19] = '\0';
        strncpy(keyDist[keyDistCount].className, exams[examIdx].assignedClassName, 99);
        keyDist[keyDistCount].className[99] = '\0';
        strncpy(keyDist[keyDistCount].fromTeacher, currentUser, 49);
        keyDist[keyDistCount].fromTeacher[49] = '\0';
        strncpy(keyDist[keyDistCount].toStudent, "CLASS", 49);
        
        // --- SECURE KEYS ---
        keyDist[keyDistCount].publicKeyE = exams[examIdx].exam_e;
        keyDist[keyDistCount].publicKeyN = exams[examIdx].exam_n;
        keyDist[keyDistCount].p = exams[examIdx].exam_p;
        keyDist[keyDistCount].q = exams[examIdx].exam_q;
        
        // === THIS WAS THE MISSING LINE FIX ===
        keyDist[keyDistCount].isClassWide = true; 
        keyDist[keyDistCount].isRead = false;
        // =====================================
        
        int classIdx = findClass(exams[examIdx].assignedClassId);
        if (classIdx != -1) {
            for (int j = 0; j < classes[classIdx].studentCount; j++) {
                if (exams[examIdx].approvedCount < 50) {
                    strncpy(exams[examIdx].approvedStudents[exams[examIdx].approvedCount], 
                            classes[classIdx].enrolledStudents[j], 49);
                    exams[examIdx].approvedStudents[exams[examIdx].approvedCount][49] = '\0';
                    exams[examIdx].approvedCount++;
                }
            }
        }
        
        exams[examIdx].keyDistributed = true;
        
        cout << endl;
        drawBoxTop();
        drawBoxLine("KEY SENT TO ENTIRE CLASS!", BOX_WIDTH, COLOR_SUCCESS);
        drawBoxMiddle();
        
        char buffer[60];
        sprintf(buffer, "Exam: %s", exams[examIdx].title);
        drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
        sprintf(buffer, "Class: %s", exams[examIdx].assignedClassName);
        drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
        
        drawBoxMiddle();
        drawBoxLine("PUBLIC KEY DISTRIBUTED", BOX_WIDTH, COLOR_HEADER);
        sprintf(buffer, "e = %lld", keyDist[keyDistCount].publicKeyE);
        drawBoxLine(buffer, BOX_WIDTH, COLOR_SUCCESS);
        sprintf(buffer, "n = %lld", keyDist[keyDistCount].publicKeyN);
        drawBoxLine(buffer, BOX_WIDTH, COLOR_SUCCESS);
        
        drawBoxBottom();
        keyDistCount++;
        
    } else if (choice == 2) {
        char studentName[50];
        setColor(COLOR_INFO);
        cout << "\n                                                    Enter student username: ";
        resetColor();
        cin.getline(studentName, 50);
        
        if (!isStudentInClass(studentName, exams[examIdx].assignedClassId)) {
            drawBoxTop();
            drawBoxLine("[!] Student not in this class!", BOX_WIDTH, COLOR_ERROR);
            drawBoxBottom();
            pauseScreen();
            return;
        }
        
        generateId(keyDist[keyDistCount].id, "KEY");
        strncpy(keyDist[keyDistCount].examId, exams[examIdx].id, 19);
        keyDist[keyDistCount].examId[19] = '\0';
        strncpy(keyDist[keyDistCount].examTitle, exams[examIdx].title, 99);
        keyDist[keyDistCount].examTitle[99] = '\0';
        strncpy(keyDist[keyDistCount].classId, exams[examIdx].assignedClassId, 19);
        keyDist[keyDistCount].classId[19] = '\0';
        strncpy(keyDist[keyDistCount].className, exams[examIdx].assignedClassName, 99);
        keyDist[keyDistCount].className[99] = '\0';
        strncpy(keyDist[keyDistCount].fromTeacher, currentUser, 49);
        keyDist[keyDistCount].fromTeacher[49] = '\0';
        strncpy(keyDist[keyDistCount].toStudent, studentName, 49);
        keyDist[keyDistCount].toStudent[49] = '\0';
        
        keyDist[keyDistCount].publicKeyE = exams[examIdx].exam_e;
        keyDist[keyDistCount].publicKeyN = exams[examIdx].exam_n;
        keyDist[keyDistCount].p = exams[examIdx].exam_p;
        keyDist[keyDistCount].q = exams[examIdx].exam_q;
        
        keyDist[keyDistCount].isClassWide = false;
        keyDist[keyDistCount].isRead = false;
        
        if (exams[examIdx].approvedCount < 50) {
            strncpy(exams[examIdx].approvedStudents[exams[examIdx].approvedCount], studentName, 49);
            exams[examIdx].approvedStudents[exams[examIdx].approvedCount][49] = '\0';
            exams[examIdx].approvedCount++;
        }
        
        cout << endl;
        drawBoxTop();
        drawBoxLine("KEY SENT TO STUDENT!", BOX_WIDTH, COLOR_SUCCESS);
        drawBoxMiddle();
        
        char buffer[60];
        sprintf(buffer, "Student: %s", studentName);
        drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
        sprintf(buffer, "Exam: %s", exams[examIdx].title);
        drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
        
        drawBoxBottom();
        keyDistCount++;
    }
    
    saveKeyDistributions();
    saveExams();
    pauseScreen();
}
void viewReceivedKeys() {
    clearScreen();
    displayRSABanner();
    displayHeader("RECEIVED EXAM KEYS");
    
    bool found = false;
    
    for (int i = 0; i < keyDistCount; i++) {
        bool forMe = (strcmp(keyDist[i].toStudent, currentUser) == 0) ||
                     (keyDist[i].isClassWide && isStudentInClass(currentUser, keyDist[i].classId));
        
        if (forMe) {
            found = true;
            cout << endl;
            drawBoxTop();
            
            if (keyDist[i].isRead) {
                drawBoxLine("[READ] Key Distribution", BOX_WIDTH, COLOR_DEFAULT);
            } else {
                drawBoxLine("[NEW] Key Distribution", BOX_WIDTH, COLOR_SUCCESS);
            }
            
            drawBoxMiddle();
            
            char buffer[60];
            sprintf(buffer, "Exam ID: %s", keyDist[i].examId);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_TITLE); // Highlighted in Magenta (Color 13)
            sprintf(buffer, "From: %s", keyDist[i].fromTeacher);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_INFO);
            sprintf(buffer, "Exam: %s", keyDist[i].examTitle);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
            sprintf(buffer, "Class: %s", keyDist[i].className);
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
            sprintf(buffer, "Type: %s", keyDist[i].isClassWide ? "Class-wide" : "Individual");
            drawBoxLineLeft(buffer, BOX_WIDTH, COLOR_DEFAULT);
            
            drawBoxMiddle();
            drawBoxLine("PUBLIC KEY FOR DECRYPTION", BOX_WIDTH, COLOR_HEADER);
            drawBoxMiddle();
            
            sprintf(buffer, "e = %lld", keyDist[i].publicKeyE);
            drawBoxLine(buffer, BOX_WIDTH, COLOR_SUCCESS);
            sprintf(buffer, "n = %lld", keyDist[i].publicKeyN);
            drawBoxLine(buffer, BOX_WIDTH, COLOR_SUCCESS);
            
            drawBoxBottom();
            
            keyDist[i].isRead = true;
        }
    }
    
    if (found) {
        saveKeyDistributions();
    } else {
        cout << endl;
        drawBoxTop();
        drawBoxLine("No exam keys received yet", BOX_WIDTH, COLOR_INFO);
        drawBoxBottom();
    }
    
    pauseScreen();
}
void crackPrivateKey(long long n, long long e, long long& d_out, long long& p_out, long long& q_out) {
    p_out = 0;
    q_out = 0;
    
    // 1. FACTORIZE N (Brute force factor finding)
    // We look for a number 'i' that divides 'n' cleanly.
    for (long long i = 2; i * i <= n; i++) {
        if (n % i == 0) {
            p_out = i;
            q_out = n / i;
            break;
        }
    }

    if (p_out == 0) return; // Failed to crack

    // 2. CALCULATE PHI (Euler's Totient)
    long long phi = (p_out - 1) * (q_out - 1);

    // 3. CALCULATE PRIVATE KEY (d)
    // d is the modular multiplicative inverse of e mod phi
    d_out = modInverse(e, phi);
}
void attemptExam() {
    clearScreen();
    displayHeader("ATTEMPT EXAM");

    // --- STEP 1: SELECT EXAM ---
    char examId[20];
    setColor(COLOR_INFO); cout << "\n                                                    Enter Exam ID to attempt: "; resetColor();
    cin.getline(examId, 20);

    int idx = findExam(examId);
    if (idx == -1) {
        drawBoxTop();
        drawBoxLine("[!] Exam not found.", BOX_WIDTH, COLOR_ERROR);
        drawBoxBottom();
        pauseScreen();
        return;
    }

    // --- STEP 2: INPUT PUBLIC KEY ---
    long long inputN, inputE;
    
    cout << endl;
    drawBoxTop(60);
    drawBoxLine("KEY CRACKING MODULE", 60, COLOR_HEADER);
    drawBoxMiddle(60);
    drawBoxLineLeft("Enter the Public Key (N, E) to break encryption.", 60, COLOR_DEFAULT);
    drawBoxBottom(60);
    cout << endl;

    setColor(COLOR_INFO); cout << "                                                    Enter Modulus (N): "; resetColor();
    if (!(cin >> inputN)) { cin.clear(); cin.ignore(); return; }
    
    setColor(COLOR_INFO); cout << "                                                    Enter Exponent (E): "; resetColor();
    if (!(cin >> inputE)) { cin.clear(); cin.ignore(); return; }
    cin.ignore(); 

    // --- STEP 3: CRACKING ANIMATION ---
    cout << endl;
    setColor(COLOR_TITLE); cout << "                                                    INITIATING FACTORIZATION ATTACK..." << endl; Sleep(500);
    setColor(COLOR_DEFAULT); cout << "                                                    Targeting Modulus N = " << inputN << endl; Sleep(300);
    
    long long calcD, calcP, calcQ;
    crackPrivateKey(inputN, inputE, calcD, calcP, calcQ);

    if (calcP == 0) {
        setColor(COLOR_ERROR); cout << "                                                    Attack Failed. N is prime or too large." << endl;
        pauseScreen(); return;
    }

    setColor(COLOR_SUCCESS); cout << "                                                    Factors Found: P=" << calcP << ", Q=" << calcQ << endl; Sleep(300);
    setColor(COLOR_INFO);    cout << "                                                    Calculated Phi(n) = " << (calcP-1)*(calcQ-1) << endl; Sleep(300);
    setColor(COLOR_HEADER);  cout << "                                                    PRIVATE KEY (d) RECOVERED: " << calcD << endl; Sleep(800);

    // --- STEP 4: DECRYPT EXAM ---
    char decryptedContent[5000];
    // Use the CALCULATED private key (calcD) to unlock the exam
    decryptMessage(exams[idx].encryptedContent, decryptedContent, calcD, inputN);

    // Basic validation: If decryption failed, it usually looks like garbage text
    if (strlen(decryptedContent) == 0) {
        setColor(COLOR_ERROR); cout << "\n                                                    Decryption yielded empty result." << endl;
        pauseScreen(); return;
    }

    clearScreen();
    displayHeader(exams[idx].title);
    
    drawBoxTop();
    drawBoxLine("EXAM UNLOCKED", BOX_WIDTH, COLOR_SUCCESS);
    drawBoxMiddle();
    setColor(COLOR_DEFAULT);
    cout << "  " << decryptedContent << endl;
    cout << endl;
    drawBoxBottom();

    // --- STEP 5: SUBMIT ANSWER ---
    cout << "\n                                                    Type your answer below (Type 'SUBMIT' on a new line to finish):\n";
    cout << "                                                    ------------------------------------------------------------\n";
    setColor(COLOR_SUCCESS);
    
    char answer[5000]; answer[0] = '\0';
    char line[1000];
    while (cin.getline(line, 1000)) {
        if (strcmp(line, "SUBMIT") == 0) break;
        strcat(answer, line);
        strcat(answer, "\n");
    }
    resetColor();

    // --- STEP 6: ENCRYPT & SAVE SUBMISSION ---
    // We encrypt the answer with the Teacher's Public Key (inputE, inputN)
    // so only the teacher can read it.
    
    generateId(assignments[assignmentCount].id, "SUB");
    strncpy(assignments[assignmentCount].studentName, currentUser, 49);
    strncpy(assignments[assignmentCount].courseName, exams[idx].id, 99);
    assignments[assignmentCount].isGraded = false;
    
    encryptMessage(answer, assignments[assignmentCount].encryptedSubmission, inputE, inputN);
    
    // Digital Signature (Student signs with their calculated private key just to prove it's them)
    long long sig = createSignature(answer, calcD, inputN);
    strncpy(assignments[assignmentCount].signature.signedBy, currentUser, 49);
    assignments[assignmentCount].signature.signatureHash = sig;
    assignments[assignmentCount].signature.isVerified = true;

    assignmentCount++;
    saveAssignments();

    cout << endl;
    drawBoxTop();
    drawBoxLine("SUBMISSION ENCRYPTED & SENT", BOX_WIDTH, COLOR_SUCCESS);
    drawBoxBottom();
    
    pauseScreen();
}
void viewSubmissions() {
    clearScreen();
    displayHeader("STUDENT SUBMISSIONS");
  
    bool found = false;
    
    const char* headers[] = {"ID", "Title", "Class", "Duration", "Key Sent", "Access"};
    int colWidths[] = {10, 18, 12, 10, 9, 8};
    int totalWidth = 71;
    
    bool headerPrinted = false;
    
    for (int i = 0; i < examCount; i++) {
        if (strcmp(exams[i].teacherName, currentUser) == 0) {
            if (!headerPrinted) {
                cout << endl;
                drawTableHeader(headers, 6, colWidths, totalWidth);
                headerPrinted = true;
            }
            
            found = true;
            char durStr[15], accessStr[10];
            sprintf(durStr, "%d min", exams[i].duration);
            sprintf(accessStr, "%d", exams[i].approvedCount);
            
            const char* row[] = {
                exams[i].id, 
                exams[i].title, 
                exams[i].assignedClassName,
                durStr,
                exams[i].keyDistributed ? "Yes" : "No",
                accessStr
            };
            drawTableRow(row, 6, colWidths, totalWidth);
        }
    }
    
    if (found) {
        drawTableBottom(6, colWidths, totalWidth);
    } else {
        cout << endl;
        drawBoxTop();
        drawBoxLine("No exams created yet", BOX_WIDTH, COLOR_INFO);
        drawBoxBottom();
    }
    
    // 2. Select Exam
    char examId[20];
    setColor(COLOR_INFO); cout << "\n                                                    Enter Exam ID to view responses: "; resetColor();
    cin.getline(examId, 20);

    // Verify ownership
    int eIdx = findExam(examId);
    int tIdx = findUser(currentUser); // Need teacher's real private key index
    
    if (eIdx == -1 || strcmp(exams[eIdx].teacherName, currentUser) != 0) {
        cout << "                                                    Access Denied.\n"; pauseScreen(); return;
    }

    bool foundSub = false;
    for (int i = 0; i < assignmentCount; i++) {
        // Find assignments linked to this exam ID
        if (strcmp(assignments[i].courseName, examId) == 0) {
            foundSub = true;
            
            // DECRYPT ANSWER
            // The student encrypted it with our Public Key, so we use our Private Key (d)
            char decryptedAnswer[5000];
           
           decryptMessage(assignments[i].encryptedSubmission, decryptedAnswer, exams[eIdx].exam_d, exams[eIdx].exam_n);

            cout << endl;
            drawBoxTop();
            char header[100]; 
            sprintf(header, "Student: %s", assignments[i].studentName);
            drawBoxLine(header, BOX_WIDTH, COLOR_HEADER);
            drawBoxMiddle();
            
            cout << "                                                     Decrypted Response :\n" << endl;
            setColor(COLOR_SUCCESS);
            cout << "                                                    " << decryptedAnswer << endl;
            resetColor();
            
            drawBoxMiddle();
            
            // Signature Verification (Optional cool feature)
            // Verify using the calculated public key E (which is mathematically valid for verification here)
            // For simplicity, we just show the hash
            char sigStr[100];
            sprintf(sigStr, "Digital Sig: %lld", assignments[i].signature.signatureHash);
            drawBoxLine(sigStr, BOX_WIDTH, COLOR_INFO);
            
            drawBoxBottom();
        }
    }

    if (!foundSub) {
        cout << "\n                                                    No submissions received for this exam yet.\n";
    }
    pauseScreen();
}
// DASHBOARD MENUS 

void teacherDashboard() {
    while (true) {
        clearScreen();
        displayTeacherBanner();
        
        char welcomeMsg[100];
        sprintf(welcomeMsg, "Welcome, Teacher %s", currentUser);
        drawBoxTop();
        drawBoxLine(welcomeMsg, BOX_WIDTH, COLOR_INFO);
        drawBoxBottom();

        cout << endl;
        displaySectionHeader("MAIN MENU");
        
        // Menu Options
        cout << endl;
        setColor(COLOR_INFO); cout << "                                                    1. "; resetColor(); cout << "Create New Class" << endl;
        setColor(COLOR_INFO); cout << "                                                    2. "; resetColor(); cout << "View My Classes" << endl;
        setColor(COLOR_INFO); cout << "                                                    3. "; resetColor(); cout << "Create New Exam" << endl;
        setColor(COLOR_INFO); cout << "                                                    4. "; resetColor(); cout << "View My Exams" << endl;
        setColor(COLOR_INFO); cout << "                                                    5. "; resetColor(); cout << "Distribute Exam Keys" << endl;
        setColor(COLOR_INFO); cout << "                                                    6. "; resetColor(); cout << "View Student Submissions" << endl;
        cout << "                                                    -----------------------------" << endl;
        setColor(COLOR_TITLE); cout << "                                                    7. "; resetColor(); cout << "View My RSA Key Info" << endl;
        setColor(COLOR_TITLE); cout << "                                                    8. "; resetColor(); cout << "RSA Encryption Demo" << endl;
        setColor(COLOR_TITLE); cout << "                                                    9. "; resetColor(); cout << "Digital Signature Demo" << endl;
        cout << "                                                    -----------------------------" << endl;
        setColor(COLOR_ERROR); cout << "                                                    0. "; resetColor(); cout << "Logout" << endl;

        cout << endl;
        drawBoxTop(BOX_WIDTH);
        drawBoxLine("Enter your choice: ", BOX_WIDTH, COLOR_HEADER);
        drawBoxBottom(BOX_WIDTH);
        
        int choice;
        cout << "  > ";
        cin >> choice;
        cin.ignore();

        switch (choice) {
            case 1: createClass(); break;
            case 2: viewMyClasses(); break;
            case 3: createExam(); break;
            case 4: viewMyExams(); break;
            case 5: distributeExamKey(); break;
            case 6: viewSubmissions(); break;
            case 7: viewMyKeyInfo(); break;
            case 8: rsaEncryptionDemo(); break;
            case 9: digitalSignatureDemo(); break;
            case 0: return; // Returns to main()
            default:
                cout << "\n  Invalid choice!";
                cin.get();
        }
    }
}

void studentDashboard() {
    while (true) {
        clearScreen();
        displayStudentBanner();

        char welcomeMsg[100];
        sprintf(welcomeMsg, "Welcome, Student %s", currentUser);
        drawBoxTop();
        drawBoxLine(welcomeMsg, BOX_WIDTH, COLOR_SUCCESS);
        drawBoxBottom();

        cout << endl;
        displaySectionHeader("MAIN MENU");

        // Menu Options
        cout << endl;
        setColor(COLOR_SUCCESS); cout << "                                                    1. "; resetColor(); cout << "Join a Class" << endl;
        setColor(COLOR_SUCCESS); cout << "                                                    2. "; resetColor(); cout << "View Enrolled Classes" << endl;
        setColor(COLOR_SUCCESS); cout << "                                                    3. "; resetColor(); cout << "View Received Exam Keys" << endl;
        setColor(COLOR_SUCCESS); cout << "                                                    4. "; resetColor(); cout << "Attempt Exam" << endl; 
        cout << "                                                    -----------------------------" << endl;
        setColor(COLOR_TITLE); cout << "                                                    5. "; resetColor(); cout << "View My RSA Key Info" << endl;
        setColor(COLOR_TITLE); cout << "                                                    6. "; resetColor(); cout << "RSA Encryption Demo" << endl;
        setColor(COLOR_TITLE); cout << "                                                    7. "; resetColor(); cout << "Digital Signature Demo" << endl;
        cout << "                                                    -----------------------------" << endl;
        setColor(COLOR_ERROR); cout << "                                                    0. "; resetColor(); cout << "Logout" << endl;

        cout << endl;
        drawBoxTop(BOX_WIDTH);
        drawBoxLine("Enter your choice: ", BOX_WIDTH, COLOR_HEADER);
        drawBoxBottom(BOX_WIDTH);

        int choice;
        cout << "  > ";
        cin >> choice;
        cin.ignore();

        switch (choice) {
            case 1: joinClass(); break;
            case 2: viewMyEnrolledClasses(); break;
            case 3: viewReceivedKeys(); break;
            case 4: attemptExam(); break;
            case 5: viewMyKeyInfo(); break;
            case 6: rsaEncryptionDemo(); break;
            case 7: digitalSignatureDemo(); break;
            case 0: return; // Returns to main()
            default:
                cout << "\n  Invalid choice!";
                cin.get();
        }
    }
}

//  MAIN FUNCTION 

int main() {
    // 1. Initialization
    srand(time(0));  // Seed random number generator
    loadAllData();   // Load all database files
    syncIdCounter();
    SetConsoleTitle("Secure Exam Management System (RSA)");

    bool running = true;

    while (running) {
        clearScreen();
        displayMainBanner();
        
        cout << endl;
        drawBoxTop();
        drawBoxLine("SECURE EXAM SYSTEM", BOX_WIDTH, COLOR_HEADER);
        drawBoxMiddle();
        drawBoxLine("Built with RSA Encryption", BOX_WIDTH, COLOR_INFO);
        drawBoxBottom();

        cout << endl;
        
        // Centered Menu
        int consoleWidth, consoleHeight;
        getConsoleDimensions(consoleWidth, consoleHeight);
        int padding = (consoleWidth - 30) / 2;
        
        for(int i=0; i<padding; i++) cout << " ";
        setColor(COLOR_SUCCESS); cout << "1. LOGIN" << endl;
        
        for(int i=0; i<padding; i++) cout << " ";
        setColor(COLOR_INFO); cout << "2. REGISTER NEW USER" << endl;
        
        for(int i=0; i<padding; i++) cout << " ";
        setColor(COLOR_TITLE); cout << "3. RSA FEATURES DEMO" << endl;
        
        for(int i=0; i<padding; i++) cout << " ";
        setColor(COLOR_ERROR); cout << "0. EXIT APPLICATION" << endl;
        resetColor();

        cout << endl;
        drawBoxTop(40);
        drawBoxLine("Select an option", 40, COLOR_DEFAULT);
        drawBoxBottom(40);

        int choice;
        cout << "  > ";
        if (!(cin >> choice)) {
            // Handle non-integer input
            cin.clear();
            cin.ignore(1000, '\n');
            choice = -1;
        }
        cin.ignore();

        switch (choice) {
            case 1:
                if (login()) {
                    if (strcmp(currentRole, "teacher") == 0) {
                        teacherDashboard();
                    } else if (strcmp(currentRole, "student") == 0) {
                        studentDashboard();
                    }
                    // Reset current user on logout
                    currentUser[0] = '\0';
                    currentRole[0] = '\0';
                }
                break;
            case 2:
                registerUser();
                break;
            case 3:
                // Quick access to demos without login (optional)
                while(true) {
                    clearScreen();
                    displayRSABanner();
                    cout << "\n  [1] Encryption Demo\n  [2] Signature Demo\n  [0] Back\n\n  > ";
                    int dChoice;
                    cin >> dChoice;
                    cin.ignore();
                    if (dChoice == 1) {
                         // Temporary user key for demo if not logged in
                         if (userCount == 0) { 
                             cout << "  [!] Please register a user first to generate keys.\n"; 
                             pauseScreen(); 
                         } else {
                             // Use first user's keys for demo
                             strcpy(currentUser, users[0].username); 
                             rsaEncryptionDemo(); 
                             currentUser[0] = '\0';
                         }
                    }
                    else if (dChoice == 2) {
                        if (userCount == 0) {
                             cout << "  [!] Please register a user first.\n"; 
                             pauseScreen(); 
                        } else {
                            strcpy(currentUser, users[0].username);
                            digitalSignatureDemo();
                            currentUser[0] = '\0';
                        }
                    }
                    else break;
                }
                break;
            case 0:
                running = false;
                break;
            default:
                drawBoxTop();
                drawBoxLine("Invalid Selection", BOX_WIDTH, COLOR_ERROR);
                drawBoxBottom();
                pauseScreen();
        }
    }

    // Exit Sequence
    clearScreen();
    drawBoxTop();
    
    saveAllData();
    drawBoxLine("Data Saved Successfully.", BOX_WIDTH, COLOR_SUCCESS);
    drawBoxLine("Goodbye!", BOX_WIDTH, COLOR_HEADER);
    drawBoxBottom();
    
    return 0;
}