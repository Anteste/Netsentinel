CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -Iinclude

CORE_SRCS := src/Alert.cpp src/AlertManager.cpp src/DetectionEngine.cpp \
	src/FileLogger.cpp src/IdsConfig.cpp src/NetworkEvent.cpp \
	src/PortScanRule.cpp src/SshBruteForceRule.cpp

APP_SRCS := src/main.cpp src/EventSimulator.cpp
TEST_SRCS := tests/IdsTests.cpp src/EventSimulator.cpp

.PHONY: all test clean

all: ids ids_tests

ids: $(CORE_SRCS) $(APP_SRCS)
	$(CXX) $(CXXFLAGS) $(CORE_SRCS) $(APP_SRCS) -o $@

ids_tests: $(CORE_SRCS) $(TEST_SRCS)
	$(CXX) $(CXXFLAGS) $(CORE_SRCS) $(TEST_SRCS) -o $@

test: ids_tests
	./ids_tests

clean:
	rm -f ids ids_tests
