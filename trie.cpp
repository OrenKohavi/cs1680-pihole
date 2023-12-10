#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>

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

class URLTrie {
  private:
    TrieNode *root;

  public:
    URLTrie() {
        root = new TrieNode("");
    }

    ~URLTrie() {
        cout << "Trie Deallocation: I am lazy and do not want to deallocate the Trie, this leaks memory!" << endl;
    }

    void insert(vector<string> url) {
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

    /**
     * Returns true if the trie contains the exact domain name.
     * Returns false if the input is a subdomain of a domain in the trie.
    */
    bool contains_exact(vector<string> url) {
        TrieNode *current_node = this->root;
        for (string domain : url) {
            if (current_node->children.contains(domain)) {
                current_node = current_node->children[domain];
                //Great, this part of the trie already exists, just move on
            } else {
                //Doesn't work if we don't have an exact match!
                return false;
            }
        }
        //If we reach the end of the loop, then the input url is contained within the trie
        //If the last node is a leaf, then the input url is an exact match
        return current_node->isLeaf;
    }

    /**
     * Returns true if the trie contains the exact domain name, or if the input is a subdomain of a domain in the trie.
    */
    bool contains_subdomain(vector<string> url) {
        TrieNode *current_node = this->root;
        for (string domain : url) {
            if (current_node->children.contains(domain)) {
                current_node = current_node->children[domain];
                //Great, this part of the trie already exists, just move on
            } else {
                //Reached the end of the trie, but we still have more input to process
                //If the trie is truly done (i.e. the node is a leaf) then we have a subdomain match
                //If the current node is not a leaf, then it's not a subdomain match, so return false.
                break;
            }
        }
        //If we reach the end of the loop, then the input url is contained within the trie
        //If the last node is a leaf, then the input url is an exact match
        return current_node->isLeaf;
    }
};
