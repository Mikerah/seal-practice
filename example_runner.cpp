#include "example_runner.h"

using namespace std;
using namespace seal;

int main() {
    cout << "Running basic SEAL examples" << endl;

    cout << "Running Simple Arithmetic Example" << endl;
    main_simple_arithmetic();

    cout << "Running Simple Floating Point Example" << endl;
    main_simple_floating_point();

    cout << "Running Simple Arrays/Vectors Example" << endl;
    main_arrays();

    cout << "Running Conditional Selection Example" << endl;
    main_conditional_select();
}