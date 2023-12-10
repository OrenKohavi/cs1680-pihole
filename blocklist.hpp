#pragma once

#include <string>
#include <vector>

int init_blocklists(bool exact_match);
bool is_whitelisted(std::vector<std::string> &url);
bool is_blacklisted(std::vector<std::string> &url);
