#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>

#include "trie.hpp"

using namespace std;

class TrieNode {
  public:
    unordered_map<string, TrieNode *> children;
    bool isLeaf;
    string domain;

    TrieNode(string domain_param) {
        isLeaf = true;
        domain = domain_param;
        children = unordered_map<string, TrieNode *>();
    }

    void AddChild(string domain) {
        //Sanity check, this key doesn't already exist
        if (children.contains(domain)) [[unlikely]] {
            throw runtime_error("Trying to add key '" + domain + "' to TrieNode, but it already exists!");
        }
        children.emplace(domain, new TrieNode(domain));
        isLeaf = false;
    }
};

URLTrie::URLTrie() {
    this->exact_match = false;
    root = new TrieNode("");
}

URLTrie::~URLTrie() {
    cout << "Trie Deallocation: I am lazy and do not want to deallocate the Trie, this leaks memory!" << endl;
}

void URLTrie::insert(vector<string> url) {
    TrieNode *current_node = this->root;
    for (string domain : url) {
        if (current_node->children.contains(domain)) {
            //Great, this part of the trie already exists, just move on
        } else {
            //Need to add this node to the trie!
            current_node->AddChild(domain);
        }
        current_node = current_node->children[domain];
    }
}

bool URLTrie::contains(vector<string> &url) {
    if (url.empty()) [[unlikely]] {
        throw runtime_error("Trying to check if empty vector is in trie!");
    }
    TrieNode *current_node = this->root;
    for (string domain : url) {
        if (current_node->children.contains(domain)) {
            current_node = current_node->children[domain];
            // Great, this part of the trie already exists, just move on
        } else {
            // Doesn't work if we don't have an exact match!
            if (this->exact_match) {
                return false;
            } else {
                return current_node->isLeaf;
            }
        }
    }
    // If we reach the end of the loop, then the input url is contained within the trie
    // If the last node is a leaf, then the input url is an exact match
    return current_node->isLeaf;
}
