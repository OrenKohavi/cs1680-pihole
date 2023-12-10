#include <iostream>
#include <filesystem>
#include <array>

using namespace std;

constexpr const char *BLOCKLIST_DIRECTORY = "./blocklists";
constexpr array<const char *, 1> blocklistURLs = {
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
};

int init_blocklists() {
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
    return 0;
}

