# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.26

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/antoniajanuszewicz/CLionProjects/DecodingExample

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/antoniajanuszewicz/CLionProjects/DecodingExample/cmake-build-local

# Include any dependencies generated for this target.
include CMakeFiles/DecodingExample.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/DecodingExample.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/DecodingExample.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/DecodingExample.dir/flags.make

CMakeFiles/DecodingExample.dir/main.cpp.o: CMakeFiles/DecodingExample.dir/flags.make
CMakeFiles/DecodingExample.dir/main.cpp.o: /Users/antoniajanuszewicz/CLionProjects/DecodingExample/main.cpp
CMakeFiles/DecodingExample.dir/main.cpp.o: CMakeFiles/DecodingExample.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/antoniajanuszewicz/CLionProjects/DecodingExample/cmake-build-local/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/DecodingExample.dir/main.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/DecodingExample.dir/main.cpp.o -MF CMakeFiles/DecodingExample.dir/main.cpp.o.d -o CMakeFiles/DecodingExample.dir/main.cpp.o -c /Users/antoniajanuszewicz/CLionProjects/DecodingExample/main.cpp

CMakeFiles/DecodingExample.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/DecodingExample.dir/main.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/antoniajanuszewicz/CLionProjects/DecodingExample/main.cpp > CMakeFiles/DecodingExample.dir/main.cpp.i

CMakeFiles/DecodingExample.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/DecodingExample.dir/main.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/antoniajanuszewicz/CLionProjects/DecodingExample/main.cpp -o CMakeFiles/DecodingExample.dir/main.cpp.s

# Object files for target DecodingExample
DecodingExample_OBJECTS = \
"CMakeFiles/DecodingExample.dir/main.cpp.o"

# External object files for target DecodingExample
DecodingExample_EXTERNAL_OBJECTS =

DecodingExample: CMakeFiles/DecodingExample.dir/main.cpp.o
DecodingExample: CMakeFiles/DecodingExample.dir/build.make
DecodingExample: /usr/local/lib/libOPENFHEpke.1.1.1.dylib
DecodingExample: /usr/local/lib/libOPENFHEbinfhe.1.1.1.dylib
DecodingExample: /usr/local/lib/libOPENFHEcore.1.1.1.dylib
DecodingExample: CMakeFiles/DecodingExample.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/antoniajanuszewicz/CLionProjects/DecodingExample/cmake-build-local/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable DecodingExample"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/DecodingExample.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/DecodingExample.dir/build: DecodingExample
.PHONY : CMakeFiles/DecodingExample.dir/build

CMakeFiles/DecodingExample.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/DecodingExample.dir/cmake_clean.cmake
.PHONY : CMakeFiles/DecodingExample.dir/clean

CMakeFiles/DecodingExample.dir/depend:
	cd /Users/antoniajanuszewicz/CLionProjects/DecodingExample/cmake-build-local && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/antoniajanuszewicz/CLionProjects/DecodingExample /Users/antoniajanuszewicz/CLionProjects/DecodingExample /Users/antoniajanuszewicz/CLionProjects/DecodingExample/cmake-build-local /Users/antoniajanuszewicz/CLionProjects/DecodingExample/cmake-build-local /Users/antoniajanuszewicz/CLionProjects/DecodingExample/cmake-build-local/CMakeFiles/DecodingExample.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/DecodingExample.dir/depend
