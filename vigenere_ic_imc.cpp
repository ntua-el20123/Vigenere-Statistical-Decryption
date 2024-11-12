#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <tuple>
#include <unordered_set>
#include <sstream>

using namespace std;

// Function to divide text into r(estimated key length) columns; columns hold ONLY a-z
vector<string> columnize(const string &text, const int &r)
{
    vector<string> columns(r, "");
    int r_index = 0;
    for(size_t i = 0; i < text.size(); i++) {
        if(isalpha(text[i])) {
            columns[r_index % r] += tolower(text[i]);
            r_index++;
        }
    }
    return columns;
}

// Function to calculate Index of Coincidence (IC) for a given text
double calculateIC(const string &text) {
    int freq[26] = {0};
    int N = 0;
    for(char ch : text) {
        if(isalpha(ch)) {
            freq[ch - 'a']++;
            N++;
        }
    }
    double ic = 0;
    for (int f : freq) {
        ic += f * (f - 1);
    }
    return N > 1 ? ic / (N * (N - 1)) : 0;
}

vector<int> estimateKeyLength(const string &ciphertext) 
{
    vector<tuple<int, double>> probableLengths;
    // r_estimate = (IC_english - IC_random) / (IC_text - IC_random) 
    int r_estimate = (0.065 - 0.038) / (calculateIC(ciphertext) - 0.038);

    for(int keyLen = 1; keyLen <= r_estimate * 2; keyLen++) {
        auto columns = columnize(ciphertext, keyLen);

        double avgIC = 0.0;
        for(auto &col: columns) {
            avgIC += calculateIC(col);
        }
        avgIC /= keyLen;

        probableLengths.push_back({keyLen, avgIC});
    }

    sort(probableLengths.begin(), probableLengths.end(), [](auto &a, auto &b) { return get<1>(a) > get<1>(b); });

    vector<int> topKeyLengths;
    for (int i = 0; i < probableLengths.size(); i++) {
        // DEBUG
        // cout << get<0>(probableLengths[i]) << " ";
        topKeyLengths.push_back(get<0>(probableLengths[i]));
    }
    
    cout << endl;

    return topKeyLengths;
}

// Function to calculate IMC between two columns for a specific shift
double calculateIMC(const string &col1, const string &col2) {
    vector<int> freq1(26, 0);
    vector<int> freq2(26, 0);
    for(char ch : col1) {
        freq1[ch - 'a']++;
    }
    for(char ch : col2) {
        freq2[ch - 'a']++;
    }

    double imc = 0.0;
    for(int i = 0; i < 26; i++) {
        imc += (freq1[i] * freq2[i]);
    }
    return imc / (col1.size() * col2.size());
}

// Function to find the best key using the relative shift method between columns
string findBestKey(const string &ciphertext, int keyLength) {
    string key = "";
    auto columns = columnize(ciphertext, keyLength);

    // Calculate the relative shifts for each pair of columns
    vector<int> shifts(keyLength, 0);  // Assume the shift of the first column is 0

    for (int i = 1; i < keyLength; i++) {
        double bestIMC = 0.0;
        int bestShift = 0;

        // Try each possible shift between column 0 and column i
        for (int shift = 0; shift < 26; shift++) {
            string shiftedCol = "";
            for (char ch : columns[i]) {
                shiftedCol += ((ch - 'a' - shift + 26) % 26) + 'a';
            }

            double imc = calculateIMC(columns[0], shiftedCol);
            if (imc > bestIMC) {
                bestIMC = imc;
                bestShift = shift;
            }
        }

        // Store the relative shift for column i compared to column 0
        shifts[i] = bestShift;
    }

    // Convert shifts into the key by fixing the first character's shift at 0
    for (int shift : shifts) {
        key += (char)('a' + shift);
    }

    return key;
}

// Function to decrypt with a given key
string decipherVigenere(const string &ciphertext, const string &key) 
{
    string plaintext = "";
    int keyLength = key.length(), keyIndex = 0;

    for(size_t i = 0; i < ciphertext.length(); i++) {
        if(isalpha(ciphertext[i])) {
            plaintext += (ciphertext[i] - key[keyIndex % keyLength] + 26) % 26 + 'a';
            keyIndex++;
        } else {
            plaintext += ciphertext[i];
        }
    }
    return plaintext;
}

// Function to reverse a monoalphabetic substitution cipher
string ceasar(string cipherText, int shift) 
{
    string plainText;

    for(int i = 0; i < cipherText.size(); i++) {
        char x = (cipherText[i] - 'a' + shift + 26) % 26 + 'a';
        plainText.push_back(x);
    }
    return plainText;
}

bool containsCommonWords(const string& text) {
    // Define the 5 most common words in the English dictionary
    unordered_set<string> commonWords = {"the", "be", "to", "of", "and"};

    // Split the input string into words
    istringstream stream(text);
    string word;
    while (stream >> word) {
        // Check if the word is in the set of common words
        if (commonWords.find(word) != commonWords.end()) {
            return true;
        }
    }
    return false;
}

int main()
{
    ifstream inputFile("ciphertext.txt");
    if (!inputFile) {
        cerr << "Unable to open file ciphertext.txt";
        return 1;
    }
    string ciphertext((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
    inputFile.close();

    // Preprocess text
    transform(ciphertext.begin(), ciphertext.end(), ciphertext.begin(), ::tolower);
    cout << "CIPHERTEXT: " << endl;
    cout << ciphertext << endl;
    printf("\n");

    int counter = 1;
    for(auto k: estimateKeyLength(ciphertext)) {
        if(counter > 5) break;

        vector<tuple<string, double, string>> plaintextWic;
        string bKey = findBestKey(ciphertext, k);
        for(int i = 0; i < 26; i++) {
            string rotatedKey = ceasar(bKey, i);
            string plaintext = decipherVigenere(ciphertext, rotatedKey);
            if(containsCommonWords(plaintext)) {
                double ic = calculateIC(plaintext);
                plaintextWic.push_back({plaintext, ic, rotatedKey});
                // DEBUG
                // cout << "KEY " << counter << ": " << rotatedKey << ", " << ic << endl;
            }
        }
        sort(plaintextWic.begin(), plaintextWic.end(), [](auto &a, auto &b) { return abs(get<1>(a) - 0.065) < abs(get<1>(b) - 0.065); });
        if(plaintextWic.empty()) {
            cout << endl << "No common words found for key length " << k << endl;
            continue;
        }
        auto maxIC = plaintextWic[0];

        cout << "KEY " << counter << ": " << endl;
        cout << get<2>(maxIC) << endl;
        cout << "PLAINTEXT" << counter << ": " << endl;
        cout << get<0>(maxIC) << endl;
        cout << "IC " << counter << ": " << endl;
        cout << get<1>(maxIC) << endl;
        cout << endl;
        counter++;
    }

    return 0;
}