/*
 * IFF SDK samples (https://mr-te.ch/iff-sdk) are licensed under MIT License.
 *
 * Copyright (c) 2022-2026 MRTech SK, s.r.o.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// std
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

// json
#include <nlohmann/json.hpp>

// IFF SDK
#include <iff.h>

#ifdef __aarch64__
#pragma message("Make sure that configuration file uses \"jetson\" encoder type, unless it's Jetson Thor")
#endif


constexpr char CONFIG_FILENAME[] = "imagefilter.json";

int main()
{
    nlohmann::json config;
    try
    {
        config = nlohmann::json::parse(std::ifstream(CONFIG_FILENAME), nullptr, true, true);
    }
    catch(const std::exception& e)
    {
        std::cerr << "Invalid configuration provided: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    const auto it_chains = config.find("chains");
    if(it_chains == config.end())
    {
        std::cerr << "Invalid configuration provided: missing `chains` section\n";
        return EXIT_FAILURE;
    }
    if(!it_chains->is_array())
    {
        std::cerr << "Invalid configuration provided: section `chains` must be an array\n";
        return EXIT_FAILURE;
    }
    if(it_chains->empty())
    {
        std::cerr << "Invalid configuration provided: section `chains` must not be empty\n";
        return EXIT_FAILURE;
    }
    const auto it_iff = config.find("IFF");
    if(it_iff == config.end())
    {
        std::cerr << "Invalid configuration provided: missing `IFF` section\n";
        return EXIT_FAILURE;
    }

    iff_initialize(it_iff->dump().c_str());

    std::map<std::string, iff_chain_handle_t> chains;
    for(const auto& chain_config : *it_chains)
    {
        const auto chain_handle = iff_create_chain(chain_config.dump().c_str(),
                                                   [](const char* element_name, int error_code, void*)
                                                   {
                                                       std::ostringstream message;
                                                       message << "Chain element `" << element_name << "` reported an error: " << error_code;
                                                       iff_log(IFF_LOG_LEVEL_ERROR, "imagefilter", message.str().c_str());
                                                   },
                                                   nullptr);
        chains.emplace(chain_config["id"].get<std::string>(), chain_handle);
    }

    std::mutex mutex;
    std::condition_variable cv;
    std::queue<std::pair<void*, iff_image_metadata>> processing_queue;
    bool stop_processing = false;
    const auto process = [&]()
    {
        std::unique_lock<std::mutex> lock(mutex);
        while(true)
        {
            while(!processing_queue.empty())
            {
                const auto [buffer, metadata] = processing_queue.front();
                processing_queue.pop();
                lock.unlock();

                // draw crosshair
                const auto char_ptr = reinterpret_cast<uint8_t*>(buffer);
                constexpr size_t bpp = 3;
                const auto stride = metadata.width * bpp + metadata.padding;
                for(uint32_t y = metadata.height / 2 - 100; y < metadata.height / 2 + 100; ++y)
                {
                    for(uint32_t x = metadata.width / 2 - 2; x < metadata.width / 2 + 2; ++x)
                    {
                        char_ptr[y * stride + x * bpp + 0] = 0;
                        char_ptr[y * stride + x * bpp + 1] = 0;
                        char_ptr[y * stride + x * bpp + 2] = 255;
                    }
                }
                for(uint32_t x = metadata.width / 2 - 100; x < metadata.width / 2 + 100; ++x)
                {
                    for(uint32_t y = metadata.height / 2 - 2; y < metadata.height / 2 + 2; ++y)
                    {
                        char_ptr[y * stride + x * bpp + 0] = 0;
                        char_ptr[y * stride + x * bpp + 1] = 0;
                        char_ptr[y * stride + x * bpp + 2] = 255;
                    }
                }

                iff_push_import_buffer(chains["import"], "importer", buffer, metadata);
                lock.lock();
            }
            if(stop_processing)
            {
                return;
            }
            cv.wait(lock);
        }
    };
    auto processing_thread = std::thread([&](){ process(); });

    using exporter_t = std::function<void(const void*, size_t, const iff_image_metadata*)>;
    exporter_t export_callback = [&](const void* const data, const size_t size, const iff_image_metadata* const metadata)
    {
        size_t buffer_size;
        const auto buffer = iff_get_import_buffer(chains["import"], "importer", &buffer_size);
        if(buffer != nullptr)
        {
            if(buffer_size >= size)
            {
                std::memcpy(buffer, data, size);
                {
                    std::scoped_lock<std::mutex> lock(mutex);
                    processing_queue.emplace(buffer, *metadata);
                }
                cv.notify_all();
            }
            else
            {
                std::ostringstream message;
                message << "Got import buffer size less than export buffer size (" << buffer_size << " < " << size << ")";
                iff_log(IFF_LOG_LEVEL_ERROR, "imagefilter", message.str().c_str());
                iff_release_buffer(chains["import"], "importer", buffer);
            }
        }
    };
    iff_set_export_callback(chains["export"], "exporter",
                            [](const void* const data, const size_t size, iff_image_metadata* const metadata, void* const private_data)
                            {
                                const auto export_function = reinterpret_cast<const exporter_t*>(private_data);
                                (*export_function)(data, size, metadata);
                            },
                            &export_callback);

    iff_execute(chains["export"], nlohmann::json{{"exporter", {{"command", "on"}}}}.dump().c_str(), [](const char*, void*){}, nullptr);

    iff_log(IFF_LOG_LEVEL_INFO, "imagefilter", "Press Enter to terminate the program");
    std::getchar();

    iff_execute(chains["export"], nlohmann::json{{"exporter", {{"command", "off"}}}}.dump().c_str(), [](const char*, void*){}, nullptr);
    {
        std::scoped_lock<std::mutex> lock(mutex);
        stop_processing = true;
    }
    cv.notify_all();
    processing_thread.join();

    for(const auto& [chain_id, chain_handle] : chains)
    {
        iff_release_chain(chain_handle);
    }

    iff_finalize();

    return EXIT_SUCCESS;
}
