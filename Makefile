# Define the C++ compiler to use
CXX = g++

# Define any compile-time flags
CXXFLAGS = -std=c++17 -Wall -I/path/to/SEAL/include

# Define any directories containing header files
INCLUDES = 

# Define library paths and linker flags
LFLAGS = -L/path/to/SEAL/lib -lseal -lm

# Define the C++ source files
SRCS = seal_example.cpp

# Define the C++ object files
OBJS = $(SRCS:.cpp=.o)

# Define the executable file
MAIN = seal_example

all: $(MAIN)
	@echo  Compiling has been completed

$(MAIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS)

.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(MAIN)

