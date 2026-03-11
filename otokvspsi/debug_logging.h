#pragma once

#include <cstdlib>
#include <string>

namespace otokvspsi::debug {

inline bool Enabled() {
  static const bool enabled = [] {
    const char* env = std::getenv("OTOKVS_DEBUG");
    if (env == nullptr) {
      return false;
    }
    const std::string value(env);
    return value == "1" || value == "true" || value == "TRUE" ||
           value == "on" || value == "ON";
  }();
  return enabled;
}

}  // namespace otokvspsi::debug
