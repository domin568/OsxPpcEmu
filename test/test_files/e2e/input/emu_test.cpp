#include <iostream>
#include <cmath>

using namespace std;

struct Vec3
{
    float x;
    float y;
    float z;
};

int fibonacci(int n)
{
    if (n <= 1) return n;
    return fibonacci(n-1) + fibonacci(n-2);
}

float dot(const Vec3& a, const Vec3& b)
{
    return a.x*b.x + a.y*b.y + a.z*b.z;
}

void matrixMultiply(float A[3][3], float B[3][3], float R[3][3])
{
    for(int i=0;i<3;i++)
        for(int j=0;j<3;j++)
        {
            R[i][j] = 0.0f;
            for(int k=0;k<3;k++)
                R[i][j] += A[i][k] * B[k][j];
        }
}

int main()
{
    cout << "PPC Emulator Test Start\n";

    // Integer stress
    int sum = 0;
    for(int i=0;i<100000;i++)
        sum += (i ^ (i << 3)) & 0xFF;

    cout << "Integer sum: " << sum << endl;

    // Floating point stress
    double fsum = 0.0;
    for(int i=1;i<50000;i++)
        fsum += sqrt((double)i) * sin(i);

    cout << "FP sum: " << fsum << endl;

    // Struct + FPU
    Vec3 a = {1.0f, 2.0f, 3.0f};
    Vec3 b = {4.0f, 5.0f, 6.0f};
    cout << "Dot: " << dot(a,b) << endl;

    // Matrix multiply
    float A[3][3] = {
        {1,2,3},
        {4,5,6},
        {7,8,9}
    };

    float B[3][3] = {
        {9,8,7},
        {6,5,4},
        {3,2,1}
    };

    float R[3][3];
    matrixMultiply(A,B,R);

    cout << "Matrix R[0][0]: " << R[0][0] << endl;

    // Branch + recursion
    cout << "Fib(10): " << fibonacci(10) << endl;

    // Memory stress
    int buffer[1024];
    for(int i=0;i<1024;i++)
        buffer[i] = i * i;

    long checksum = 0;
    for(int i=0;i<1024;i++)
        checksum += buffer[i];

    cout << "Memory checksum: " << checksum << endl;

    cout << "PPC Emulator Test End\n";
    return 0;
}