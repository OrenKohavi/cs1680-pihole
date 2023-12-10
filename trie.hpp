#pragma once

#include <vector>
#include <string>

class TrieNode;

class URLTrie {
  private:
    TrieNode *root; // Pointer to root node

  public:
    URLTrie();
    ~URLTrie();
    void insert(std::vector<std::string> url);
    bool contains(std::vector<std::string> &url);
    bool exact_match;
};