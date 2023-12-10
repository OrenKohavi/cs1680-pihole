#include <iostream>
#include <filesystem>
#include <array>
#include <fstream>
#include <ranges>
#include <algorithm>

#include "trie.cpp"

using namespace std;

constexpr const char *BLOCKLIST_DIRECTORY = "./blocklists";
constexpr array<const char *, 1> blocklistURLs = {
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
};

// Custom hash function for a vector of strings
struct VectorHash {
    size_t operator()(const std::vector<std::string> &v) const {
        std::hash<std::string> hasher;
        size_t seed = 0;
        for (const std::string &s : v) {
            seed ^= hasher(s) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }
};

static URLTrie blocklist = URLTrie();
//Maps from domain name vector to IP address
static auto whitelist = unordered_map<vector<string>, string, VectorHash>();;

int init_blocklists(bool exact_match) {
    // Create the blocklist folder if it doesn't already exist
    filesystem::path folderPath(BLOCKLIST_DIRECTORY);
    if (!filesystem::exists(folderPath)) {
        filesystem::create_directory(folderPath);
        cout << "Created folder: " << folderPath << endl;
    } else {
        cout << "Folder already exists: " << folderPath << endl;
    }

    // Download the latest version of all the blocklists by just running wget, if they don't already exist (and are less than 1 week old)
    for (const char *url : blocklistURLs) {
        auto filename = filesystem::path(url).filename();
        if (filesystem::exists(folderPath / filename)) {
            cout << "File '" + string(filename) + "' already exists" << endl;
            continue;
        }
        string command = "wget -P " + string(BLOCKLIST_DIRECTORY) + " " + url +  " -O " + string(url);
        cout << "Running command: " << command << endl;
        int status = system(command.c_str());
        if (status == -1) {
            // system() failed to execute
            cerr << "Failed to execute command: " << command << endl;
            return -1;
        } else {
            // Check the exit status of the wget command
            int exitStatus = WEXITSTATUS(status);
            if (exitStatus != 0) {
                // wget command failed
                cerr << "wget command failed with status: " << exitStatus << ". Command: " << command << endl;
                return -1;
            }
        }
    }

    //Parse the blocklists into the trie
    blocklist.exact_match = exact_match;
    for (const auto &entry : filesystem::directory_iterator(folderPath)) {
        if (entry.is_regular_file()) {
            cout << "Parsing file: " << entry.path() << endl;
            //Parse the hosts file into the trie
            //Read a line at a time
            ifstream file(entry.path());
            string line;
            while (getline(file, line)) {
                //Skip comments
                if (line[0] == '#') [[unlikely]] {
                    continue;
                }
                //Skip blank lines
                if (line.empty()) [[unlikely]] {
                    continue;
                }
                //Skip IPV6 lines, so filter out any line that contains a colon
                if (line.find(':') != string::npos) [[unlikely]] {
                    continue;
                }
                //For remaining lines, parse the IP and domain name
                //Split the line on whitespace
                auto spacePos = std::ranges::find(line, ' ');
                std::string ip(line.begin(), spacePos);
                std::string name(spacePos + 1, line.end());

                // Split the domain name on periods
                vector<string> url;
                auto periodPos = std::ranges::find(name, '.');
                while (periodPos != name.end()) {
                    url.emplace_back(name.begin(), periodPos);
                    name = string(periodPos + 1, name.end());
                    periodPos = std::ranges::find(name, '.');
                }
                url.emplace_back(name.begin(), name.end()); // Add the last part of the domain name
                // Reverse the url so that it is in the correct order for the trie
                reverse(url.begin(), url.end());

                if (ip != "0.0.0.0") [[unlikely]] {
                    //These are whitelisted things, so just add them to the whitelist
                    whitelist.emplace(url, ip);
                } else {
                    //These are blacklisted things, so add them to the blocklist trie
                    blocklist.insert(url);
                }
            }
        }
    }
    return 0;
}

bool is_whitelisted(const vector<string> &url) {
    //If the URL is in the map, then it is whitelisted
    return whitelist.contains(url);
}

bool is_blacklisted(const vector<string> &url) {
    //If the URL is in the trie, then it is blacklisted
    return blocklist.contains(url);
}