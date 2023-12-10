#pragma once

class TrieNode {
  public:
    std::unordered_map<std::string, TrieNode *> children;
    bool isLeaf;
    std::string domain;

    TrieNode(std::string domain_param);
    void AddChild(std::string domain);
};

class URLTrie {
  private:
    TrieNode *root;

  public:
    URLTrie();
    ~URLTrie();
    void insert(std::vector<std::string> url);
    bool contains_exact(std::vector<std::string> url);
    bool contains_subdomain(std::vector<std::string> url);
};