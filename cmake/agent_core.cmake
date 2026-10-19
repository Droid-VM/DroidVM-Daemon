# Android Java resources and the native runner consume these same script files.
set(agent_core_root "${CMAKE_CURRENT_LIST_DIR}/../agent")
foreach(agent_part preamble chpasswd autogrow epilogue finalize)
    set(agent_input "${agent_core_root}/scripts/droidvm-agent/${agent_part}.sh")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${agent_input}")
    file(READ "${agent_input}" agent_text)
    string(REPLACE "\r\n" "\n" agent_text "${agent_text}")
    string(FIND "${agent_text}" ")DVM_AGENT\"" agent_delimiter)
    if(NOT agent_delimiter EQUAL -1)
        message(FATAL_ERROR "Agent script collides with the C++ literal delimiter: ${agent_input}")
    endif()
    set("DROIDVM_AGENT_${agent_part}" "${agent_text}")
endforeach()
configure_file("${CMAKE_CURRENT_LIST_DIR}/agent_scripts_data.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/agent_scripts_data.h" @ONLY NEWLINE_STYLE LF)
add_library(droidvm_agent_core STATIC
    "${agent_core_root}/scripts.cpp"
    "${agent_core_root}/plan.cpp"
    "${agent_core_root}/protocol.cpp"
    "${agent_core_root}/runner.cpp"
    "${agent_core_root}/rescue_sessions.cpp")
target_include_directories(droidvm_agent_core PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(droidvm_agent_core PUBLIC droidvm_wire droidvm_identity)
target_compile_features(droidvm_agent_core PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(droidvm_agent_core PRIVATE /utf-8 /W4 /WX)
else()
    target_compile_options(droidvm_agent_core PRIVATE -Wall -Wextra -Werror)
endif()

function(droidvm_add_agent_contracts)
    foreach(agent_contract plan protocol scripts runner rescue_sessions)
        add_executable(droidvm_agent_${agent_contract}_contract
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tests/agent_${agent_contract}_contract.cpp")
        target_link_libraries(droidvm_agent_${agent_contract}_contract PRIVATE droidvm_agent_core)
        if(MSVC)
            target_compile_options(droidvm_agent_${agent_contract}_contract PRIVATE /utf-8 /W4 /WX)
        else()
            target_compile_options(droidvm_agent_${agent_contract}_contract PRIVATE -Wall -Wextra -Werror)
        endif()
        add_test(NAME agent_${agent_contract}_contract COMMAND droidvm_agent_${agent_contract}_contract)
    endforeach()
endfunction()
