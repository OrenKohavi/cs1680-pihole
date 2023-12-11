#pragma once

#include <string>
#include <vector>

int init_blocklists(bool exact_match);
const char* is_whitelisted(std::vector<std::string> &url);
bool is_blacklisted(std::vector<std::string> &url);
