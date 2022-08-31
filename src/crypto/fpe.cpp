/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <chrono>   // NOLINT [build/c++11]
#include <sstream>
#include "./phantom.hpp"
#include "crypto/fpe.hpp"
#include "crypto/aes.hpp"
#include "./phantom_types.hpp"
#include "./phantom_memory.hpp"
#include "crypto/aes_fpe_ff1.hpp"
#include "crypto/aes_fpe_ff3_1.hpp"


namespace phantom {


std::unique_ptr<fpe_ctx> fpe::create_ctx(const phantom_vector<uint8_t>& user_key,
    fpe_type_e type, fpe_format_e format, const phantom_vector<uint8_t>& tweak)
{
    std::unique_ptr<fpe_ctx> ctx;

    aes_keylen_e aeslen = (AES_FF1_128 == type || AES_FF3_1_128 == type)? AES_128 :
                          (AES_FF1_192 == type || AES_FF3_1_192 == type)? AES_192 :
                                                                          AES_256;

    switch (type)
    {
#if defined(ENABLE_FPE_AES_FF1)
    case AES_FF1_256:
    case AES_FF1_192:
    case AES_FF1_128:
    {
        switch (format)
        {
        case FPE_STR_NUMERIC:            ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_ALPHANUMERIC:       ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_LOWER_ALPHANUMERIC: ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_UPPER_ALPHANUMERIC: ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_ALPHABETICAL:       ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_LOWER_ALPHABETICAL: ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_UPPER_ALPHABETICAL: ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_ASCII_PRINTABLE:    ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_UTF8:               ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_STR_UTF16:              ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_NUMBER_INT:             ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        case FPE_ISO8601:                ctx = crypto::aes_fpe_ff1<uint8_t>::create_ctx(user_key, aeslen, tweak); break;
        default: throw std::runtime_error("Unsupported FF1 format");
        }
    } break;
#endif

#if defined(ENABLE_FPE_AES_FF3_1)
    case AES_FF3_1_256:
    case AES_FF3_1_192:
    case AES_FF3_1_128:
    {
        switch (format)
        {
        case FPE_STR_NUMERIC:            ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_ALPHANUMERIC:       ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_LOWER_ALPHANUMERIC: ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_UPPER_ALPHANUMERIC: ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_ALPHABETICAL:       ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_LOWER_ALPHABETICAL: ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_UPPER_ALPHABETICAL: ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_ASCII_PRINTABLE:    ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_UTF8:               ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_STR_UTF16:              ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_NUMBER_INT:             ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        case FPE_ISO8601:                ctx = crypto::aes_fpe_ff3_1<uint8_t>::create_ctx(user_key, aeslen, tweak);
                                         break;
        default: throw std::runtime_error("Unsupported FF3 format");
        }
    } break;
#endif

    default: throw std::runtime_error("Unsupported FPE type");
    }

    ctx->type   = type;
    ctx->format = format;
    return ctx;
}

void fpe::encrypt_str(std::unique_ptr<fpe_ctx>& ctx, std::string& inout)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    phantom_vector<std::string> inout_vec = { inout };
    encrypt_str(ctx, inout_vec);
    inout.replace(inout.begin(), inout.end(), inout_vec[0]);
#endif
}

void fpe::encrypt_str(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout)
{
    phantom_vector<uint8_t> out_str, in_str;
    uint8_t radix;

    for (size_t i=0; i < inout.size(); i++) {
        phantom_vector<pad_code> pad;
        map(ctx->format, inout[i], in_str, pad, radix);

        switch (ctx->type)
        {
#if defined(ENABLE_FPE_AES_FF1)
        case AES_FF1_128:
        case AES_FF1_192:
        case AES_FF1_256: crypto::aes_fpe_ff1<uint8_t>::encrypt(ctx, radix, in_str, out_str); break;
#endif
#if defined(ENABLE_FPE_AES_FF3_1)
        case AES_FF3_1_128:
        case AES_FF3_1_192:
        case AES_FF3_1_256: crypto::aes_fpe_ff3_1<uint8_t>::encrypt(ctx, radix, in_str, out_str); break;
#endif
        default: exit(-1);
        }

        unmap(ctx->format, out_str, inout[i], pad);
    }
}

void fpe::encrypt_number(std::unique_ptr<fpe_ctx>& ctx, int& inout, int range)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    phantom_vector<int> inout_vec = { inout };
    encrypt_number(ctx, inout_vec, range);
    inout = inout_vec[0];
#endif
}

void fpe::encrypt_number(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<int>& inout, int range)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    for (size_t i=0; i < inout.size(); i++) {
        std::string inout_str = std::to_string(inout[i]);
        inout_str.insert(0, range - inout_str.size(), '0');
        encrypt_str(ctx, inout_str);
        inout[i] = std::stoi(inout_str);
    }
#endif
}

void fpe::encrypt_float(std::unique_ptr<fpe_ctx>& ctx, double& inout, int range, int precision)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    phantom_vector<double> inout_vec = { inout };
    encrypt_float(ctx, inout_vec, range, precision);
    inout = inout_vec[0];
#endif
}

void fpe::encrypt_float(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<double>& inout, int range, int precision)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    for (size_t i=0; i < inout.size(); i++) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(precision) << inout[i];
        std::string inout_str = ss.str();

        assert((range + precision + 1) >= static_cast<int>(inout_str.size()));
        inout_str.insert(0, (range + precision + 1) - inout_str.size(), '0');
        encrypt_str(ctx, inout_str);
        inout[i] = std::stod(inout_str);
    }
#endif
}

void fpe::encrypt_iso8601(std::unique_ptr<fpe_ctx>& ctx, std::string& inout)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    phantom_vector<std::string> inout_vec = { inout };
    encrypt_iso8601(ctx, inout_vec);
    inout.replace(inout.begin(), inout.end(), inout_vec[0]);
#endif
}

void fpe::encrypt_iso8601(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout)
{
    int year, month, day, hour, minute, second;

    for (size_t i=0; i < inout.size(); i++) {
        parse_iso8601(inout[i], year, month, day, hour, minute, second);

        phantom_vector<uint8_t> out_date, in_date;
        phantom_vector<pad_code> pad;
        uint8_t radix;

        std::string date = std::to_string(rdn(year, month, day) - 1);
        date.insert(0, 6 - date.size(), '0');
        map(FPE_STR_NUMERIC, date, in_date, pad, radix);

        switch (ctx->type)
        {
#if defined(ENABLE_FPE_AES_FF1)
        case AES_FF1_128:
        case AES_FF1_192:
        case AES_FF1_256: crypto::aes_fpe_ff1<uint8_t>::encrypt(ctx, radix, in_date, out_date); break;
#endif
#if defined(ENABLE_FPE_AES_FF3_1)
        case AES_FF3_1_128:
        case AES_FF3_1_192:
        case AES_FF3_1_256: crypto::aes_fpe_ff3_1<uint8_t>::encrypt(ctx, radix, in_date, out_date); break;
#endif
        default: exit(-1);
        }

        unmap(FPE_STR_NUMERIC, out_date, date, pad);
        inverse_rdn(std::stoi(date) + 1, year, month, day);

        phantom_vector<uint32_t> sec_in_codepoints = { static_cast<uint32_t>(((hour*60) + minute)*60 + second) },
                                                     sec_out_codepoints;

        switch (ctx->type)
        {
#if defined(ENABLE_FPE_AES_FF1)
        case AES_FF1_128:
        case AES_FF1_192:
        case AES_FF1_256: crypto::aes_fpe_ff1<uint32_t>::encrypt(ctx, 86400, sec_in_codepoints, sec_out_codepoints);
                          break;
#endif
#if defined(ENABLE_FPE_AES_FF3_1)
        case AES_FF3_1_128:
        case AES_FF3_1_192:
        case AES_FF3_1_256: crypto::aes_fpe_ff3_1<uint32_t>::encrypt(ctx, 86400, sec_in_codepoints, sec_out_codepoints);
                            break;
#endif
        default: exit(-1);
        }

        hour   = sec_out_codepoints[0] / 3600;
        minute = (sec_out_codepoints[0] - hour * 3600) / 60;
        second = sec_out_codepoints[0] - (hour * 60 + minute) * 60;

        inout[i] = amend_iso8601(inout[i], year, month, day, hour, minute, second);
    }
}

void fpe::decrypt_str(std::unique_ptr<fpe_ctx>& ctx, std::string& inout)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    phantom_vector<std::string> inout_vec = { inout };
    decrypt_str(ctx, inout_vec);
    inout.replace(inout.begin(), inout.end(), inout_vec[0]);
#endif
}

void fpe::decrypt_str(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout)
{
    phantom_vector<uint8_t> out_str, in_str;
    uint8_t radix;

    for (size_t i=0; i < inout.size(); i++) {
        phantom_vector<pad_code> pad;
        map(ctx->format, inout[i], in_str, pad, radix);

        switch (ctx->type)
        {
#if defined(ENABLE_FPE_AES_FF1)
        case AES_FF1_128:
        case AES_FF1_192:
        case AES_FF1_256: crypto::aes_fpe_ff1<uint8_t>::decrypt(ctx, radix, in_str, out_str); break;
#endif
#if defined(ENABLE_FPE_AES_FF3_1)
        case AES_FF3_1_128:
        case AES_FF3_1_192:
        case AES_FF3_1_256: crypto::aes_fpe_ff3_1<uint8_t>::decrypt(ctx, radix, in_str, out_str); break;
#endif
        default: exit(-1);
        }

        unmap(ctx->format, out_str, inout[i], pad);
    }
}

void fpe::decrypt_number(std::unique_ptr<fpe_ctx>& ctx, int& inout, int range)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    phantom_vector<int> inout_vec = { inout };
    decrypt_number(ctx, inout_vec, range);
    inout = inout_vec[0];
#endif
}

void fpe::decrypt_number(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<int>& inout, int range)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    for (size_t i=0; i < inout.size(); i++) {
        std::string inout_str = std::to_string(inout[i]);
        inout_str.insert(0, range - inout_str.size(), '0');
        decrypt_str(ctx, inout_str);
        inout[i] = std::stoi(inout_str);
    }
#endif
}

void fpe::decrypt_float(std::unique_ptr<fpe_ctx>& ctx, double& inout, int range, int precision)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    phantom_vector<double> inout_vec = { inout };
    decrypt_float(ctx, inout_vec, range, precision);
    inout = inout_vec[0];
#endif
}

void fpe::decrypt_float(std::unique_ptr<fpe_ctx>& ctx,
    phantom_vector<double>& inout, int range, int precision)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    for (size_t i=0; i < inout.size(); i++) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(precision) << inout[i];
        std::string s = ss.str();

        assert((range + precision + 1) >= static_cast<int>(s.size()));
        s.insert(0, (range + precision + 1) - s.size(), '0');
        decrypt_str(ctx, s);
        inout[i] = std::stod(s);
    }
#endif
}

void fpe::decrypt_iso8601(std::unique_ptr<fpe_ctx>& ctx, std::string& inout)
{
#if defined(ENABLE_FPE_AES_FF1) || defined(ENABLE_FPE_AES_FF3_1)
    phantom_vector<std::string> inout_vec = { inout };
    decrypt_iso8601(ctx, inout_vec);
    inout.replace(inout.begin(), inout.end(), inout_vec[0]);
#endif
}

void fpe::decrypt_iso8601(std::unique_ptr<fpe_ctx>& ctx, phantom_vector<std::string>& inout)
{
    int year, month, day, hour, minute, second;

    for (size_t i=0; i < inout.size(); i++) {
        parse_iso8601(inout[i], year, month, day, hour, minute, second);

        phantom_vector<uint8_t> out_date, in_date;
        phantom_vector<pad_code> pad;
        uint8_t radix;

        std::string date = std::to_string(rdn(year, month, day) - 1);
        date.insert(0, 6 - date.length(), '0');
        map(FPE_STR_NUMERIC, date, in_date, pad, radix);

        switch (ctx->type)
        {
#if defined(ENABLE_FPE_AES_FF1)
        case AES_FF1_128:
        case AES_FF1_192:
        case AES_FF1_256: crypto::aes_fpe_ff1<uint8_t>::decrypt(ctx, radix, in_date, out_date); break;
#endif
#if defined(ENABLE_FPE_AES_FF3_1)
        case AES_FF3_1_128:
        case AES_FF3_1_192:
        case AES_FF3_1_256: crypto::aes_fpe_ff3_1<uint8_t>::decrypt(ctx, radix, in_date, out_date); break;
#endif
        default: exit(-1);
        }

        unmap(FPE_STR_NUMERIC, out_date, date, pad);
        inverse_rdn(std::stoi(date) + 1, year, month, day);

        phantom_vector<uint32_t> sec_in_codepoints = { static_cast<uint32_t>(((hour*60) + minute)*60 + second) },
                                                     sec_out_codepoints;

        switch (ctx->type)
        {
#if defined(ENABLE_FPE_AES_FF1)
        case AES_FF1_128:
        case AES_FF1_192:
        case AES_FF1_256: crypto::aes_fpe_ff1<uint32_t>::decrypt(ctx, 86400, sec_in_codepoints, sec_out_codepoints);
                          break;
#endif
#if defined(ENABLE_FPE_AES_FF3_1)
        case AES_FF3_1_128:
        case AES_FF3_1_192:
        case AES_FF3_1_256: crypto::aes_fpe_ff3_1<uint32_t>::decrypt(ctx, 86400, sec_in_codepoints, sec_out_codepoints);
                            break;
#endif
        default: exit(-1);
        }

        hour   = sec_out_codepoints[0] / 3600;
        minute = (sec_out_codepoints[0] - hour * 3600) / 60;
        second = sec_out_codepoints[0] - (hour * 60 + minute) * 60;

        inout[i] = amend_iso8601(inout[i], year, month, day, hour, minute, second);
    }
}

void fpe::map(fpe_format_e format, const std::string& in, phantom_vector<uint8_t>& out,
    phantom_vector<pad_code>& pad, uint8_t& radix)
{
    uint8_t max = 0;
    switch (format)
    {
    case FPE_STR_NUMERIC:            max = 10; radix = 10; break;
    case FPE_STR_ALPHANUMERIC:       max = 62; radix = 62; break;
    case FPE_STR_LOWER_ALPHANUMERIC: max = 36; radix = 36; break;
    case FPE_STR_UPPER_ALPHANUMERIC: max = 36; radix = 36; break;
    case FPE_STR_ALPHABETICAL:       max = 52; radix = 52; break;
    case FPE_STR_LOWER_ALPHABETICAL: max = 26; radix = 26; break;
    case FPE_STR_UPPER_ALPHABETICAL: max = 26; radix = 26; break;
    case FPE_STR_ASCII_PRINTABLE:    max = 96; radix = 96; break;
    case FPE_NUMBER_INT:             max = 10; radix = 10; break;
    default:                         {};
    }

    out = phantom_vector<uint8_t>();
    for (size_t i=0, j=0; i < in.size(); i++) {
        uint8_t value = 0;
        switch (format)
        {
        case FPE_STR_NUMERIC:            value = in[i] - 48; break;
        case FPE_STR_ALPHANUMERIC:       value = (in[i] >= 97 && in[i] <= 122)? in[i] - 97 + 36 :
                                                 (in[i] >= 65 && in[i] <= 90)?  in[i] - 65 + 10 :
                                                 (in[i] >= 48 && in[i] <= 57)?  in[i] - 48 : radix; break;
        case FPE_STR_ASCII_PRINTABLE:    value = in[i] - 32; break;
        case FPE_STR_LOWER_ALPHANUMERIC: value = (in[i] >= 97 && in[i] <= 122)? in[i] - 97 + 10 :
                                                 (in[i] >= 48 && in[i] <= 57)?  in[i] - 48 : radix; break;
        case FPE_STR_UPPER_ALPHANUMERIC: value = (in[i] >= 65 && in[i] <= 90)? in[i] - 65 + 10 :
                                                 (in[i] >= 48 && in[i] <= 57)?  in[i] - 48 : radix; break;
        case FPE_STR_ALPHABETICAL:       value = (in[i] >= 97 && in[i] <= 122)? in[i] - 97 + 26 :
                                                 (in[i] >= 65 && in[i] <= 90)?  in[i] - 65 : radix; break;
        case FPE_STR_LOWER_ALPHABETICAL: value = in[i] - 97; break;
        case FPE_STR_UPPER_ALPHABETICAL: value = in[i] - 65; break;
        case FPE_NUMBER_INT:             value = in[i] - 48; break;
        default:                         {};
        }

        if (value >= max) {
            pad.push_back({static_cast<uint16_t>(in[i]), j});
        }
        else {
            out.push_back(value);
            j++;
        }
    }
}

void fpe::unmap(fpe_format_e format, const phantom_vector<uint8_t>& in, std::string& out,
    const phantom_vector<pad_code>& pad)
{
    phantom_vector<pad_code>::const_iterator c_it = pad.cbegin();
    out = std::string();
    for (size_t i=0; i < in.size(); i++) {
        while (c_it != pad.cend() && c_it->position == i) { out.push_back(c_it->codeword); c_it++; }

        uint8_t value = 0;
        switch (format)
        {
        case FPE_STR_NUMERIC:            value = in[i] + 48; break;
        case FPE_STR_ALPHANUMERIC:       value = (in[i] >= 36)? in[i] + 61 :
                                                 (in[i] >= 10)? in[i] + 55 :
                                                                in[i] + 48; break;
        case FPE_STR_ASCII_PRINTABLE:    value = in[i] + 32; break;
        case FPE_STR_LOWER_ALPHANUMERIC: value = (in[i] >= 10)? in[i] + 87 : in[i] + 48; break;
        case FPE_STR_UPPER_ALPHANUMERIC: value = (in[i] >= 10)? in[i] + 55 : in[i] + 48; break;
        case FPE_STR_ALPHABETICAL:       value = (in[i] >= 26)? in[i] + 71 : in[i] + 65; break;
        case FPE_STR_LOWER_ALPHABETICAL: value = in[i] + 97; break;
        case FPE_STR_UPPER_ALPHABETICAL: value = in[i] + 65; break;
        case FPE_NUMBER_INT:             value = in[i] + 48; break;
        default:                         {};
        }
        out.push_back(value);
    }
    while (c_it != pad.cend()) {
        out.push_back(c_it->codeword);
        c_it++;
    }
}

bool fpe::parse_iso8601(const std::string& iso8601, int& year, int& month, int& day,
            int& hours, int& minutes, int& seconds)
{
    if (iso8601.size() < 19) {
        return false;
    }
    if (iso8601[4] != '-' || iso8601[7] != '-' || iso8601[10] != 'T' || iso8601[13] != ':' || iso8601[16] != ':') {
        return false;
    }

    std::string yyyy = iso8601.substr(0, 4);
    std::string mm   = iso8601.substr(5, 2);
    std::string dd   = iso8601.substr(8, 2);
    std::string hour = iso8601.substr(11, 2);
    std::string min  = iso8601.substr(14, 2);
    std::string sec  = iso8601.substr(17, 2);

    year    = std::stoi(yyyy);
    month   = std::stoi(mm);
    day     = std::stoi(dd);
    hours   = std::stoi(hour);
    minutes = std::stoi(min);
    seconds = std::stoi(sec);

    return true;
}

std::string fpe::amend_iso8601(const std::string& iso8601, int year, int month, int day,
    int hours, int minutes, int seconds)
{
    std::string yyyy = std::to_string(year);
    std::string mm   = std::to_string(month);
    std::string dd   = std::to_string(day);
    std::string hour = std::to_string(hours);
    std::string min  = std::to_string(minutes);
    std::string sec  = std::to_string(seconds);

    yyyy.insert(0, 4 - yyyy.size(), '0');
    mm.insert(0, 2 - mm.size(), '0');
    dd.insert(0, 2 - dd.size(), '0');
    hour.insert(0, 2 - hour.size(), '0');
    min.insert(0, 2 - min.size(), '0');
    sec.insert(0, 2 - sec.size(), '0');

    std::string out = iso8601;
    out.replace(0, 4, yyyy);
    out.replace(5, 2, mm);
    out.replace(8, 2, dd);
    out.replace(11, 2, hour);
    out.replace(14, 2, min);
    out.replace(17, 2, sec);
    return out;
}

uint32_t fpe::rdn(int y, int m, int d)
{
    /* Rata Die day one is 0001-01-01, Monday */
    if (m < 3) {
        y--;
        m += 12;
    }
    return 365*y + y/4 - y/100 + y/400 + (153*m - 457)/5 + d - 306;
}

void fpe::inverse_rdn(int rdn, int& year, int& month, int& day)
{
    float z = rdn + 306;
    float a = floorf((z - 0.25) / 36524.25);
    float b = z - 0.25 + a - floorf(a/4);
    float y = floorf(b / 365.25);
    int c = z + a - floorf(a/4) - floorf(365.25 * y);
    double m, tmp = (535 * c + 48950) / 16384;
    modf(tmp, &m);
    int f = static_cast<int>((979 * m - 2918)) >> 5;

    day = c - f;
    if (m > 12) {
        y++;
        m -= 12;
    }
    month = m;
    year = y;

    assert(month >= 1 && month <= 12);
    assert(year < 10000);
}

}  // namespace phantom
