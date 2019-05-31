#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <iomanip>
#include "utf8/utf8.h"
#include "ucs2.h"

namespace
{
#if 0
    std::vector<std::uint16_t> utf8_to_utf16(std::string const& input)
    {
        std::vector<std::uint16_t> result;
        utf8::utf8to16(begin(input), end(input), std::back_inserter(result));

        return result;
    }

    std::string encode_to_pdu(std::string const& message)
    {
        // TODO: If the length is longer than 70 (or even less for header-space) characters, we need to split into two (or more) messages!
        // TODO: Add headers for multi-message sequencing
        // TODO: The function should return a vector of PDU encoded messages;
        // TODO: each message should be a complete message including header and data

        std::string result;

        result += "00";    // Start with the non-existent SMSC information
        result += "1100";  // Unknown
        result += "00";    // Length of number
        result += "91";    // Number format (international)
        result += "00";    // Protocol id
        result += "08";    // Data encoding (16 bit UCS2)
        result += "AA";    // Valid period

        std::ostringstream oss;

        auto message16 = utf8_to_utf16(message);

        // The length of the text (multiplied by 2 since we have a 16-bit encoding)
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << message16.size() * 2;
        result += oss.str();

        // Add the message
        for (char16_t c : message16)
        {
            oss.str("");
            oss << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << c;

            result += oss.str();
        }

        return result;
    }

    unsigned hex_to_uint(char c)
    {
        if (std::isdigit(c))
            return c - '0';
        else if (std::isxdigit(c))
            return std::tolower(c) - 'a' + 10;  // Relies on ASCII
        else
            return ' ';
    }

    // Convert a string of octects into a vector of bytes
    std::vector<std::uint8_t> octets_to_bytes(std::string const& data)
    {
        std::vector<std::uint8_t> result;

        for (auto nibble = begin(data); nibble != end(data);)
        {
            unsigned n1 = hex_to_uint(*nibble++);
            unsigned n2 = hex_to_uint(*nibble++);
            result.push_back(static_cast<char>(n1 << 4u | n2));
        }

        return result;
    }

    std::string decode_from_pdu(std::string const& message)
    {
        // TODO: Use `octets_to_bytes` for *all* of the message
        // TODO: Then we don't have to bother about nibbles or do string comparisons
        // TODO: Should not be hard to get ranges of bytes using iterators

        static char const *const gsm7_to_utf8[] = {
            "@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\n", "Ø", "ø", "\r", "Å", "å",
            "Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ", "Σ", "Θ", "Ξ", "\x1b", "Æ", "æ", "ß", "É",
            " ", "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?",
            "¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
            "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§",
            "¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
            "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à",
        };

        std::string smsc_length = message.substr(0, 2);
        size_t current_pos = 2;

        // Skip SMSC information
        if (smsc_length != "00")
        {
            unsigned n1 = hex_to_uint(smsc_length[0]);
            unsigned n2 = hex_to_uint(smsc_length[1]);

            current_pos += (n1 << 4u | n2) * 2;  // *2 because two characters per byte
        }

        std::string type = message.substr(current_pos, 2); current_pos += 2;  // 11 = submit, 04 = deliver
        std::string message_ref = message.substr(current_pos, 2); current_pos += 2;
        std::string address_length_octet = message.substr(current_pos, 2); current_pos += 2;
        std::string address_type = message.substr(current_pos, 2); current_pos += 2;

        size_t address_length = stoul(address_length_octet, nullptr, 16);
        if (address_length % 2 != 0)
        {
            // Uneven address length, add one to get the extra padding digit
            ++address_length;
        }

        // Skip address (sender phone number)
        current_pos += address_length / 2;  // Divide by 2, because the address length is the number of single digits, not octets

        std::string protocol_id    = message.substr(current_pos, 2); current_pos += 2;
        std::string encoding_octet = message.substr(current_pos, 2); current_pos += 2;
        if (type == "04")
        {
            // SMS DELIVER (receiving)
            // Get 7 octets (semi-octets) for timestamp
            std::string timestamp  = message.substr(current_pos, 14); current_pos += 14;
        }
        else if (type == "11")
        {
            // SMS SUBMIT (sending)
            // Get one octet for validity
            // TODO: This is optional, see bits 4 and 3 of "first" octet?
            std::string validity   = message.substr(current_pos, 2); current_pos += 2;
        }
        std::string length_octet   = message.substr(current_pos, 2); current_pos += 2;
        std::string data           = message.substr(current_pos);  // The remainder of the message

        size_t length = stoul(length_octet, nullptr, 16);

        std::string result;

        if (encoding_octet == "00")
        {
            // 7-bit encoding

            // First convert the string of octets into a vector of bytes
            auto bytes = octets_to_bytes(data);

            if (length > 0)
            {
                // Get the first septet and convert to a character
                result += gsm7_to_utf8[bytes[0] & 0x7f];
            }

            for (size_t i = 1; i < bytes.size(); ++i)
            {
                unsigned bits = i % 7;

                std::uint8_t previous = bytes[i - 1];
                std::uint8_t current  = bytes[i];

                if (bits == 0)
                {
                    // Special case
                    result += gsm7_to_utf8[previous >> 1];
                }

                // Get the masking bit pattern from the number of bits
                std::uint8_t mask = 0;
                for (size_t  j    = 0; j < bits; ++j)
                {
                    mask |= 1u << j;
                }

                // Get the bits from the previous byte
                previous &= mask << (8u - bits);

                // Shift up and mask out the irrelevant bits from the current byte
                current <<= bits;
                current &= ~mask;
                current &= 0x7f;

                // Combine current and previous bytes to form the final value
                // And get the character it corresponds to
                result += gsm7_to_utf8[current | (previous >> (8u - bits))];
            }
        }
        else if (encoding_octet == "04")
        {
            // 8-bit encoded

            // Verification
            if (std::stoull(length_octet, nullptr, 16) != data.size() / 2)  // Each character occupies two hexadecimal digits
            {
                // Message length not the same as data length
                return "";
            }

            // This is basically a straight copy
            for (auto nibble = begin(data); nibble != end(data);)
            {
                unsigned n1 = hex_to_uint(*nibble++);
                unsigned n2 = hex_to_uint(*nibble++);
                result += static_cast<char>(n1 << 4u | n2);
            }
        }
        else if (encoding_octet == "08")
        {
            // 16-bit encoded

            // Verification
            if (std::stoull(length_octet, nullptr, 16) != data.size() / 2)
            {
                // Message length not the same as data length
                return "";
            }

            // First convert the data string into a series of bytes
            std::vector<std::uint16_t> temp;

            for (auto nibble = begin(data); nibble != end(data);)
            {
                unsigned n1 = hex_to_uint(*nibble++);
                unsigned n2 = hex_to_uint(*nibble++);
                unsigned n3 = hex_to_uint(*nibble++);
                unsigned n4 = hex_to_uint(*nibble++);
                temp.push_back(static_cast<std::uint16_t>(n1 << 12u | n2 << 8u | n3 << 4u | n4));
            }

            // Convert the byte vector into an UTF-8 encoded string
            utf8::utf16to8(begin(temp), end(temp), std::back_inserter(result));
        }
        else
        {
            return "";
        }

        return result;
    }
#endif

    // --------------------------------------------------------------

    unsigned hex_to_uint(char c)
    {
        if (std::isdigit(c))
            return c - '0';
        else if (std::isxdigit(c))
            return std::tolower(c) - 'a' + 10;  // Relies on ASCII
        else
            return ' ';
    }

    // Convert a string of octects into a vector of bytes
    std::vector<std::uint8_t> octets_to_bytes(std::string const& data)
    {
        std::vector<std::uint8_t> result;

        for (auto nibble = begin(data); nibble != end(data);)
        {
            unsigned n1 = hex_to_uint(*nibble++);
            unsigned n2 = hex_to_uint(*nibble++);
            result.push_back(static_cast<char>(n1 << 4u | n2));
        }

        return result;
    }

    std::vector<std::uint8_t> string_to_semi_bytes(std::string input)
    {
        std::vector<std::uint8_t> output;

        for (size_t i = 0; i < input.length(); i += 2)
        {
            std::string octet = input.substr(i, 2);
            std::swap(octet[0], octet[1]);

            output.push_back(hex_to_uint(octet[0]) << 4 | hex_to_uint(octet[1]));
        }

        return output;
    }

    std::string semi_bytes_to_string(std::vector<std::uint8_t> bytes)
    {
        std::string result;

        for (auto b : bytes)
        {
            std::uint8_t second = b >> 4;
            std::uint8_t first  = b & 0x0f;

            result += static_cast<char>(first + '0');
            if (second != 0x0f)
            {
                result += static_cast<char>(second + '0');
            }
        }

        return result;
    }

    std::string encode_submit(std::string number, std::string const& message, unsigned piece = 1, unsigned total_pieces = 1)
    {
        static uint8_t multi_piece_ref = 0;

        if (piece == 1 && total_pieces > 1)
        {
            ++multi_piece_ref;
        }

        std::vector<std::uint8_t> data;

        // No SMSC information
        data.push_back(0x00);

        // MTI : bit 0 and 1
        // VPF : bit 3 and 4
        // SRR : bit 5
        // UDHI: bit 6
        //
        // MTI  = 01 = SMS-SUBMIT
        // VPF  = 10 = Field present with relative integer format
        // SRR  =  0 = No status report requested
        // UDHI =  0 = No user data header (single message)
        // UDHI =  1 = User data header present (concatenated SMS, multiple messages)
        data.push_back(0x11 | 0x40 * (total_pieces > 1));

        // MR Message reference number
        data.push_back(piece);

        // Destination address
        {
            bool international = false;

            if (number.length() > 1 && number[0] == '0' && number[1] == '0')
            {
                international = true;
                number = number.substr(2);  // Strip the leading "00"
            }
            else if (number.length() > 0 && number[0] == '+')
            {
                international = true;
                number = number.substr(1);  // Stip the leading "+"
            }

            // Length of the address
            data.push_back(number.length());

            // Type of address
            // 0x80: Bit must always be set
            // 0x01: Standard telephone number
            data.push_back(0x81 | (international * 0x10) | (!international * 0x20));

            // Add filler if length is odd
            if (number.length() % 2 != 0)
            {
                number += 'f';
            }

            // Add the number itself
            for (auto semi_octet : string_to_semi_bytes(number))
            {
                data.push_back(semi_octet);
            }
        }

        // PID: 0x00 means SME-to-SME
        data.push_back(0x00);

        // DCS
        // Bit 7-5 = 00: General data coding indication
        // Bit   5 =  0: Uncompressed
        // Bit   4 =  0: Bits 0 and 1 are reserved and should be set to 0
        // Bit 3-2 = 10: UCS2 16-bit encoding (01 is 8-bit encoding, 00 is default 7-bit encoding)
        // Bit 1-0 = 00: Reserved as mentioned by bit 4
        data.push_back(0x08);

        // VP (Validity Period)
        // Use maximum 0xff which means 63 weeks
        data.push_back(0xff);

        // UDL: Length of the message

        std::vector<std::uint16_t> message_utf16;
        utf8::utf8to16(begin(message), end(message), std::back_inserter(message_utf16));

        data.push_back(message_utf16.size() * 2 + 6 * (total_pieces > 1));  // *2 because each character in UCS-2 is two bytes
        // 6 * (total_pieces > 1) to add the length of the user data header for multi-part messages

        if (total_pieces > 1)
        {
            data.push_back(0x05);  // User data header length
            data.push_back(0x00);  // 0x00 = Concatenated SMS
            data.push_back(0x03);  // Length of sub-header
            data.push_back(multi_piece_ref);  // Concatenated SMS reference number, must be unique for each *full* message
            data.push_back(total_pieces);     // Total number of messages
            data.push_back(piece);            // Sequence number for this message
        }

        // UD: The message itself
        for (std::uint16_t c : message_utf16)
        {
            data.push_back(c >> 8u);
            data.push_back(c & 0x00ff);
        }

        // Finally convert the whole set of bytes to a hex-string
        std::ostringstream result;

        for (auto b : data)
        {
            result << std::hex << std::setw(2) << std::uppercase << std::setfill('0') << static_cast<unsigned>(b);
        }

        return result.str();
    }

    struct message
    {
        std::string number;   // The phone number
        std::string message;  // The full message

        std::vector<std::string> pieces;  // for multi-part messages
    };

    message create_message(std::string const& number, std::string const& msg)
    {
        message m;
        m.number = number;
        m.message = msg;

        // Split into a multi-part concatenated SMS
        for (size_t current_pos = 0; current_pos < msg.length(); current_pos += 60)
        {
            m.pieces.push_back(msg.substr(current_pos, 60));
        }

        // Encode the pieces
        for (unsigned piece = 0; piece < m.pieces.size(); ++piece)
        {
            m.pieces[piece] = encode_submit(m.number, m.pieces[piece], piece + 1, m.pieces.size());
        }

        return m;
    }

    std::string bytes_to_string_7(std::vector<std::uint8_t> const& bytes, std::uint8_t& length)
{
    static std::string const gsm7_to_utf8[] = {
        "@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\n", "Ø", "ø", "\r", "Å", "å",
        "Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ", "Σ", "Θ", "Ξ", "\x1b", "Æ", "æ", "ß", "É",
        " ", "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?",
        "¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
        "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§",
        "¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
        "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à",
    };

    static std::string const gsm7_to_utf8_escaped[] = {
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "", "", "", "^", "", "", "", "", "", "", "", "", "", "", "",
        "", "", "", "", "", "", "", "", "{", "}", "", "", "", "", "", "\\",
        "", "", "", "", "", "", "", "", "", "", "", "", "[", "~", "]", "",
        "|", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
        "", "", "", "", "", "€", "", "", "", "", "", "", "", "", "", "",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
    };

    std::string result;
    bool escape_active = false;

    if (!bytes.empty())
{
    // Get the first septet and convert to a character
    if ((bytes[0] & 0x7fu)== 0x1b)
{
    if (bytes.size() > 1)
{
    // Escaped character
    escape_active = true;
    --length;
}
else
{
// Only escape character in input, how weird!
return "";
}
}
else
{
result += gsm7_to_utf8[bytes[0] & 0x7fu];
length += gsm7_to_utf8[bytes[0] & 0x7fu].length() - 1;
}
}

for (size_t i = 1; i < bytes.size(); ++i)
{
auto table = escape_active ? gsm7_to_utf8_escaped : gsm7_to_utf8;

unsigned bits = i % 7;

std::uint8_t previous = bytes[i - 1];
std::uint8_t current  = bytes[i];

if (bits == 0)
{
// Special case
if ((previous >> 1u) == 0x1b)
{
escape_active = true;
table = gsm7_to_utf8_escaped;
--length;
}
else
{
result += table[previous >> 1u];
escape_active = false;
table = gsm7_to_utf8;
}
}

// Get the masking bit pattern from the number of bits
std::uint8_t mask = 0;
for (size_t  j    = 0; j < bits; ++j)
{
mask |= 1u << j;
}

// Get the bits from the previous byte
previous &= mask << (8u - bits);

// Shift up and mask out the irrelevant bits from the current byte
current <<= bits;
current &= ~mask;
current &= 0x7fu;

// Combine current and previous bytes to form the final value
unsigned ch = current | (previous >> (8u - bits));

if (ch == 0x1b)
{
escape_active = true;
--length;
}
else
{
// And get the character it corresponds to
result += table[ch];
escape_active = false;
length += table[ch].length() - 1;
}
}

if (bytes.size() % 7 == 0 && (bytes[bytes.size() - 1] & 0xfeu) != 0)
{
// The above algorithm lose the last character if the data length is evenly divisable by 7 and there's data in the last element
// So here's the special case where we get that last character
if (escape_active)
{
result += gsm7_to_utf8_escaped[bytes[bytes.size() - 1] >> 1u];
}
else
{
result += gsm7_to_utf8[bytes[bytes.size() - 1] >> 1u];
}
}

return result;
}

std::string bytes_to_string_8(std::vector<std::uint8_t> const& bytes)
{
return std::string(begin(bytes), end(bytes));
}

std::string bytes_to_string_16(std::vector<std::uint8_t> const& bytes)
{
std::vector<std::uint16_t> ucs2_data;

for (size_t current = 0; current < bytes.size(); current += 2)
{
ucs2_data.push_back(bytes[current + 0] << 8u | bytes[current + 1]);
}

// return ucs2::ucs2_to_utf8(ucs2_data);

std::string result;
utf8::utf16to8(begin(ucs2_data), end(ucs2_data), std::back_inserter(result));
return result;
}

bool decode_deliver(std::string const& octets, std::string& number, std::string& message)
{
    auto bytes = octets_to_bytes(octets);

    if (bytes[0] != 0)
    {
        // We got an SMSC header, skip it
        bytes = std::vector<std::uint8_t>(begin(bytes) + bytes[0] + 1, end(bytes));
    }

    std::uint8_t mti  = bytes[0] & 0x03u;
    std::uint8_t mms  = bytes[0] & 0x04u;
    std::uint8_t sri  = bytes[0] & 0x20u;
    std::uint8_t udhi = bytes[0] & 0x40u;
    std::uint8_t rp   = bytes[0] & 0x80u;

    if (mti != 0)
    {
        // Not a SMS-DELIVER command
        return false;
    }

    static_cast<void>(mms);  // Ignored
    static_cast<void>(sri);  // Ignored
    static_cast<void>(rp);   // Ignored

    // udhi is used later to help skip user-data-header fields in the user-data

    // Get the originating address (the number of the system that sent the message)
    if (bytes[1] != 0)
    {
        std::uint8_t address_length = bytes[1];
        std::uint8_t address_type = bytes[2];

        size_t address_bytes_length = (address_length + (address_length % 2 != 0)) / 2;
        auto address_bytes = std::vector<std::uint8_t>(begin(bytes) + 3, begin(bytes) + 3 + address_bytes_length);

        // Add prefix for international numbers
        if ((address_type & 0x70u) >> 4u == 1)
        {
            // TODO: Flag if "+" or "00" is preferred
            number = "+";
        }

        number += semi_bytes_to_string(address_bytes);

        // Remove all up until this point
        bytes = std::vector<std::uint8_t>(begin(bytes) + 3 + address_bytes_length, end(bytes));
    }
    else
    {
        // Remove all up until this point
        bytes = std::vector<std::uint8_t>(begin(bytes) + 1, end(bytes));
    }

    std::uint8_t pid = bytes[0];
    std::uint8_t dcs = bytes[1];

    static_cast<void>(pid);  // Ignored

    // Skip the timestamp

    std::uint8_t udl = bytes[9];

    auto data_bytes = std::vector<std::uint8_t>(begin(bytes) + 10, end(bytes));

    if (udhi)
    {
        // Skip the user data header
        std::uint8_t udhl = data_bytes[0];
        data_bytes = std::vector<std::uint8_t>(begin(data_bytes) + udhl, end(data_bytes));
        udl -= udhl;
    }

    if ((dcs & 0xc0u) != 0 || (dcs & 0x20u) != 0)
    {
        // Invalid or unhandled data coding scheme
        return false;
    }

    if (dcs == 0x00)
    {
        // The default 7-bit GSM alphabet
        message = bytes_to_string_7(data_bytes, udl);
    }
    else if ((dcs & 0x0cu) == 0x04u)
    {
        // The 8-bit alphabet
        message = bytes_to_string_8(data_bytes);
    }
    else if ((dcs & 0x0cu) == 0x08u)
    {
        // UCS-2
        message = bytes_to_string_16(data_bytes);
    }
    else
    {
        // Reserved
        return false;
    }

    return message.length() == udl;
}
}

int main()
{
    {
        auto encoded = encode_submit("+46705654429", "\xf0\x9f\x98\xae");
        std::cout << "[" << (encoded.size() / 2 - 1) << "] " << encoded << '\n';
    }

    {
        static std::string const lorem   = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        auto                     message = create_message("+46705654429", lorem);

        std::cout << "Lorem length = " << lorem.length() << ", number of pieces = " << message.pieces.size() << '\n';
        for (size_t piece = 0; piece < message.pieces.size(); ++piece)
        {
            std::cout << "Piece " << std::setw(2) << (piece + 1) << '/' << message.pieces.size() << " : [" << (message.pieces[piece].size() / 2 - 1) << "] " << message.pieces[piece]
                      << '\n';
        }
    }

    {
        std::string number;
        std::string message;

        // if (decode_deliver("07912374151616F6240B912374374521F70000318011419314802A54747A0E4ACF41613768DA9C82A0C42AA88C0FB7E1EC32C82C7FB741F3F61C4EAEBBC6EF36", number, message))
        // {
        //     std::cout << "Deliver message:\n";
        //     std::cout << "    Number : " << number << '\n';
        //     std::cout << "    Message: " << message << '\n';
        // }
        //
        // if (decode_deliver("07916407070041F0040B916407654524F900009150822125208007C1F1F85D77D301", number, message))
        // {
        //     std::cout << "Deliver message:\n";
        //     std::cout << "    Number : " << number << '\n';
        //     std::cout << "    Message: " << message << '\n';
        // }
        //
        // if (decode_deliver("07916407070041F0040B916407654524F9000091508241026380029B32", number, message))
        // {
        //     std::cout << "Deliver message:\n";
        //     std::cout << "    Number : " << number << '\n';
        //     std::cout << "    Message: " << message << '\n';
        // }
        //
        // if (decode_deliver("07916407070041F0040B916407654524F900009150824181348020D377BB0C62BFDD6750BB3C9F87CF65D03D4D47833665D03CDF16BFD9", number, message))
        // {
        //     std::cout << "Deliver message:\n";
        //     std::cout << "    Number : " << number << '\n';
        //     std::cout << "    Message: " << message << '\n';
        // }
        //
        // if (decode_deliver("07916407070041F0040B916407654524F900009150825170608003C14D19", number, message))
        // {
        //     std::cout << "Deliver message:\n";
        //     std::cout << "    Number : " << number << '\n';
        //     std::cout << "    Message: " << message << '\n';
        // }
        //
        // if (decode_deliver("07916407070041F0040B916407654524F900009150825180918004C14D5908", number, message))
        // {
        //     std::cout << "Deliver message:\n";
        //     std::cout << "    Number : " << number << '\n';
        //     std::cout << "    Message: " << message << '\n';
        // }
        //
        // if (decode_deliver("07916407070041F0040B916407654524F90000915082519031800731D98C56B3DD00", number, message))
        // {
        //     std::cout << "Deliver message:\n";
        //     std::cout << "    Number : " << number << '\n';
        //     std::cout << "    Message: " << message << '\n';
        // }
        //
        // if (decode_deliver("07916407070041F0040B916407654524F90000915082510101800831D98C56B3DD70", number, message))
        // {
        //     std::cout << "Deliver message:\n";
        //     std::cout << "    Number : " << number << '\n';
        //     std::cout << "    Message: " << message << '\n';
        // }

        if (decode_deliver("07916407070041F0040B916407654524F900089150825145648004D83DDE0A", number, message))
        {
            std::cout << "Deliver message:\n";
            std::cout << "    Number : " << number << '\n';
            std::cout << "    Message: " << message << '\n';
        }
    }
}
