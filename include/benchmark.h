// Copyright (c) 2020-2021, The TurtleCoin Developers
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef TURTLECOIN_BENCHMARK_H
#define TURTLECOIN_BENCHMARK_H

#define PERFORMANCE_ITERATIONS 1000
#define PERFORMANCE_ITERATIONS_LONG_MULTIPLIER 60
#define PERFORMANCE_ITERATIONS_LONG PERFORMANCE_ITERATIONS *PERFORMANCE_ITERATIONS_LONG_MULTIPLIER

#define BENCHMARK_PREFIX_WIDTH 70
#define BENCHMARK_COLUMN_WIDTH 10
#define BENCHMARK_PRECISION 3

#include <chrono>
#include <iomanip>
#include <iostream>

/**
 * Prints the benchmark header for a "table" like setup
 */
void benchmark_header()
{
    std::cout << std::setw(BENCHMARK_PREFIX_WIDTH) << "BENCHMARK TESTS"
              << ": " << std::setw(10) << " " << std::setw(BENCHMARK_COLUMN_WIDTH) << "Average"
              << std::setw(BENCHMARK_COLUMN_WIDTH) << "Minimum" << std::setw(BENCHMARK_COLUMN_WIDTH) << "Maximum"
              << std::endl;
}

/**
 * Performs a benchmark of the given function for the number of iterations specified
 *
 * @tparam T
 * @param function
 * @param functionName
 * @param iterations
 */
template<typename T>
void benchmark(T &&function, const std::string &functionName = "", const uint64_t iterations = PERFORMANCE_ITERATIONS)
{
    if (!functionName.empty())
    {
        std::cout << std::setw(BENCHMARK_PREFIX_WIDTH) << functionName.substr(0, BENCHMARK_PREFIX_WIDTH) << ": "
                  << std::flush;
    }

    const auto tenth = (iterations >= 10) ? iterations / 10 : 1;

    const auto start_timer = std::chrono::high_resolution_clock::now();

    uint64_t min = 0xfffffffe, max = 0;

    for (uint64_t i = 0; i < iterations; ++i)
    {
        if (i % tenth == 0)
        {
            std::cout << "." << std::flush;
        }

        const auto single_iter_timer = std::chrono::high_resolution_clock::now();

        function();

        const uint64_t single_elapsed = (std::chrono::duration_cast<std::chrono::microseconds>(
                                             std::chrono::high_resolution_clock::now() - single_iter_timer)
                                             .count())
                                        * 1;

        if (single_elapsed > max)
        {
            max = single_elapsed;
        }
        else if (single_elapsed < min && single_elapsed > 0)
        {
            min = single_elapsed;
        }
    }

    if (min > max)
    {
        min = 0;
    }

    const auto elapsed_time =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start_timer)
            .count();

    const auto avg = elapsed_time / iterations;

    std::cout << std::fixed << std::setprecision(BENCHMARK_PRECISION) << std::setw(BENCHMARK_COLUMN_WIDTH)
              << avg / 1000.0 << std::fixed << std::setprecision(BENCHMARK_PRECISION)
              << std::setw(BENCHMARK_COLUMN_WIDTH) << min / 1000.0 << std::fixed
              << std::setprecision(BENCHMARK_PRECISION) << std::setw(BENCHMARK_COLUMN_WIDTH) << max / 1000.0 << " ms"
              << std::endl;
}

#endif // TURTLECOIN_BENCHMARK_H
