#pragma once

#include <vector>
#include <string>

class URLTrie {
    public:
        bool exact_match;
        URLTrie();
        ~URLTrie();
        void insert(std::vector<std::string> url);
        bool contains(std::vector<std::string> url);
};