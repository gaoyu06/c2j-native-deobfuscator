#include "class_filter.hpp"
#include <cassert>
int main() {
    j2c::ClassFilter empty;
    assert(empty.matches("other/Class"));
    j2c::ClassFilter f;
    f.add(" obf.* ; native.* ; ;");
    assert(f.active());
    assert(f.matches("obf/Class"));
    assert(f.matches("obf.deep.Class$Inner"));
    assert(f.matches("Lnative/Loader;"));
    assert(!f.matches("obfuscated/Class"));
    assert(!f.matches("other/Class"));
    f.add("exact/Class");
    assert(f.matches("exact.Class"));
    assert(!f.matches("exact/ClassExtra"));
    j2c::ClassFilter wild;
    wild.add("obf/*Suffix;prefix*middle*end");
    assert(wild.matches("obf/deep/NameSuffix"));
    assert(!wild.matches("obf/NameSuffixExtra"));
    assert(wild.matches("prefix_one_middle_two_end"));
    assert(!wild.matches("prefix_one_end"));
    wild.add("*");
    assert(wild.matches("any/Class"));
}
