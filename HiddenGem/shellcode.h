#pragma once

// Original (decrypted) shellcode
//"\x56\x48\x8B\xF4\x48\x83\xE4\xF0\x48\x83\xEC\x20\xE8\x2F\x00\x00\x00\x48\x8B\xE6\x5E\xC3\x4C\x6F\x61\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x00\x00\x00\x6B\x00\x65\x00\x72\x00\x6E\x00\x65\x00\x6C\x00\x33\x00\x32\x00\x2E\x00\x64\x00\x6C\x00\x6C\x00\x00\x00\x48\x81\xEC\xF8\x00\x00\x00\xB8\x6B\x00\x00\x00\x66\x89\x44\x24\x70\xB8\x65\x00\x00\x00\x66\x89\x44\x24\x72\xB8\x72\x00\x00\x00\x66\x89\x44\x24\x74\xB8\x6E\x00\x00\x00\x66\x89\x44\x24\x76\xB8\x65\x00\x00\x00\x66\x01\x44\x24\x78\xB8\x6C\x00\x00\x00\x66\x89\x44\x24\x7A\xB8\x33\x00\x00\x00\x66\x89\x44\x24\x7C\xB8\x32\x00\x00\x00\x66\x89\x44\x24\x7E\xB8\x2E\x00\x00\x00\x66\x89\x84\x24\x80\x00\x00\x00\xB8\x64\x00\x00\x00\x66\x89\x84\x24\x82\x00\x00\x00\xB8\x6C\x00\x00\x00\x66\x89\x84\x24\x84\x00\x00\x00\xB8\x6C\x00\x00\x00\x66\x89\x84\x24\x86\x00\x00\x00\x33\xC0\x66\x89\x84\x24\x88\x00\x00\x00\xC6\x44\x24\x40\x4C\xC6\x44\x24\x41\x6F\xC6\x44\x24\x42\x61\xC6\x44\x24\x43\x64\xC6\x44\x24\x44\x4C\xC6\x44\x24\x45\x69\xC6\x44\x24\x46\x62\xC6\x44\x24\x47\x72\xC6\x44\x24\x48\x61\xC6\x44\x24\x49\x72\xC6\x44\x24\x4A\x79\xC6\x44\x24\x4B\x41\xC6\x44\x24\x4C\x00\xC6\x44\x24\x50\x47\xC6\x44\x24\x51\x65\xC6\x44\x24\x52\x74\xC6\x44\x24\x53\x50\xC6\x44\x24\x54\x72\xC6\x44\x24\x55\x6F\xC6\x44\x24\x56\x63\xC6\x44\x24\x57\x41\xC6\x44\x24\x58\x64\xC6\x44\x24\x59\x64\xC6\x44\x24\x5A\x72\xC6\x44\x24\x5B\x65\xC6\x44\x24\x5C\x73\xC6\x44\x24\x5D\x73\xC6\x44\x24\x5E\x00\xC6\x44\x24\x20\x75\xC6\x44\x24\x21\x73\xC6\x44\x24\x22\x65\xC6\x44\x24\x23\x72\xC6\x44\x24\x24\x33\xC6\x44\x24\x25\x32\xC6\x44\x24\x26\x2E\xC6\x44\x24\x27\x64\xC6\x44\x24\x28\x6C\xC6\x44\x24\x29\x6C\xC6\x44\x24\x2A\x00\xC6\x44\x24\x30\x4D\xC6\x44\x24\x31\x65\xC6\x44\x24\x32\x73\xC6\x44\x24\x33\x73\xC6\x44\x24\x34\x61\xC6\x44\x24\x35\x67\xC6\x44\x24\x36\x65\xC6\x44\x24\x37\x42\xC6\x44\x24\x38\x6F\xC6\x44\x24\x39\x78\xC6\x44\x24\x3A\x57\xC6\x44\x24\x3B\x00\xB8\x48\x00\x00\x00\x66\x89\x84\x24\x90\x00\x00\x00\xB8\x65\x00\x00\x00\x66\x89\x84\x24\x92\x00\x00\x00\xB8\x6C\x00\x00\x00\x66\x89\x84\x24\x94\x00\x00\x00\xB8\x6C\x00\x00\x00\x66\x89\x84\x24\x96\x00\x00\x00\xB8\x6F\x00\x00\x00\x66\x89\x84\x24\x98\x00\x00\x00\xB8\x20\x00\x00\x00\x66\x89\x84\x24\x9A\x00\x00\x00\xB8\x57\x00\x00\x00\x66\x89\x84\x24\x9C\x00\x00\x00\xB8\x6F\x00\x00\x00\x66\x89\x84\x24\x9E\x00\x00\x00\xB8\x72\x00\x00\x00\x66\x89\x84\x24\xA0\x00\x00\x00\xB8\x6C\x00\x00\x00\x66\x89\x84\x24\xA2\x00\x00\x00\xB8\x64\x00\x00\x00\x66\x89\x84\x24\xA4\x00\x00\x00\xB8\x21\x00\x00\x00\x66\x89\x84\x24\xA6\x00\x00\x00\x33\xC0\x66\x89\x84\x24\xA8\x00\x00\x00\xB8\x44\x00\x00\x00\x66\x89\x44\x24\x60\xB8\x65\x00\x00\x00\x66\x89\x44\x24\x62\xB8\x6D\x00\x00\x00\x66\x89\x44\x24\x64\xB8\x6F\x00\x00\x00\x66\x89\x44\x24\x66\xB8\x21\x00\x00\x00\x66\x89\x44\x24\x68\x33\xC0\x66\x89\x44\x24\x6A\x48\x8D\x4C\x24\x70\xE8\x35\x03\x00\x00\x48\x89\x84\x24\xB0\x00\x00\x00\x48\x83\xBC\x24\xB0\x00\x00\x00\x00\x75\x0A\xB8\x01\x00\x00\x00\xE9\xD8\x00\x00\x00\x48\x8D\x54\x24\x40\x48\x8B\x8C\x24\xB0\x00\x00\x00\xE8\xCE\x00\x00\x00\x48\x89\x84\x24\xB8\x00\x00\x00\x48\x83\xBC\x24\xB8\x00\x00\x00\x00\x75\x0A\xB8\x02\x00\x00\x00\xE9\xA9\x00\x00\x00\x48\x8D\x54\x24\x50\x48\x8B\x8C\x24\xB0\x00\x00\x00\xE8\x9F\x00\x00\x00\x48\x89\x84\x24\xC0\x00\x00\x00\x48\x83\xBC\x24\xC0\x00\x00\x00\x00\x75\x07\xB8\x03\x00\x00\x00\xEB\x7D\x48\x8B\x84\x24\xB8\x00\x00\x00\x48\x89\x84\x24\xD0\x00\x00\x00\x48\x8B\x84\x24\xC0\x00\x00\x00\x48\x89\x84\x24\xE0\x00\x00\x00\x48\x8D\x4C\x24\x20\xFF\x94\x24\xD0\x00\x00\x00\x48\x89\x84\x24\xD8\x00\x00\x00\x48\x8D\x54\x24\x30\x48\x8B\x8C\x24\xD8\x00\x00\x00\xFF\x94\x24\xE0\x00\x00\x00\x48\x89\x84\x24\xC8\x00\x00\x00\x48\x83\xBC\x24\xC8\x00\x00\x00\x00\x75\x07\xB8\x04\x00\x00\x00\xEB\x1B\x45\x33\xC9\x4C\x8D\x44\x24\x60\x48\x8D\x94\x24\x90\x00\x00\x00\x33\xC9\xFF\x94\x24\xC8\x00\x00\x00\x33\xC0\x48\x81\xC4\xF8\x00\x00\x00\xC3\x48\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x48\x83\xEC\x78\x48\x8B\x84\x24\x80\x00\x00\x00\x48\x89\x44\x24\x30\x48\x8B\x44\x24\x30\x0F\xB7\x00\x3D\x4D\x5A\x00\x00\x74\x07\x33\xC0\xE9\x02\x02\x00\x00\x48\x8B\x44\x24\x30\x48\x63\x40\x3C\x48\x8B\x8C\x24\x80\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\x48\x89\x44\x24\x40\xB8\x08\x00\x00\x00\x48\x6B\xC0\x00\x48\x8B\x4C\x24\x40\x48\x8D\x84\x01\x88\x00\x00\x00\x48\x89\x44\x24\x38\x48\x8B\x44\x24\x38\x83\x38\x00\x75\x07\x33\xC0\xE9\xBA\x01\x00\x00\x48\x8B\x44\x24\x38\x8B\x00\x89\x44\x24\x18\x8B\x44\x24\x18\x48\x03\x84\x24\x80\x00\x00\x00\x48\x89\x44\x24\x10\x48\x8B\x44\x24\x10\x8B\x40\x18\x48\x89\x44\x24\x48\x48\x8B\x44\x24\x10\x8B\x40\x1C\x89\x44\x24\x24\x48\x8B\x44\x24\x10\x8B\x40\x20\x89\x44\x24\x1C\x48\x8B\x44\x24\x10\x8B\x40\x24\x89\x44\x24\x20\x48\xC7\x44\x24\x08\x00\x00\x00\x00\xEB\x0D\x48\x8B\x44\x24\x08\x48\xFF\xC0\x48\x89\x44\x24\x08\x48\x8B\x44\x24\x48\x48\x39\x44\x24\x08\x0F\x83\x43\x01\x00\x00\x8B\x44\x24\x1C\x48\x8B\x8C\x24\x80\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\x48\x8B\x4C\x24\x08\x48\x8D\x04\x88\x48\x89\x44\x24\x58\x8B\x44\x24\x20\x48\x8B\x8C\x24\x80\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\x48\x8B\x4C\x24\x08\x48\x8D\x04\x48\x48\x89\x44\x24\x50\x8B\x44\x24\x24\x48\x8B\x8C\x24\x80\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\x48\x8B\x4C\x24\x50\x0F\xB7\x09\x48\x8D\x04\x88\x48\x89\x44\x24\x60\x48\x8B\x44\x24\x58\x8B\x00\x48\x8B\x8C\x24\x80\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\x48\x89\x44\x24\x28\x48\xC7\x04\x24\x00\x00\x00\x00\x48\xC7\x04\x24\x00\x00\x00\x00\xEB\x0B\x48\x8B\x04\x24\x48\xFF\xC0\x48\x89\x04\x24\x48\x8B\x04\x24\x48\x8B\x8C\x24\x88\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\x0F\xBE\x00\x85\xC0\x74\x45\x48\x8B\x04\x24\x48\x8B\x4C\x24\x28\x48\x03\xC8\x48\x8B\xC1\x0F\xBE\x00\x85\xC0\x74\x2F\x48\x8B\x04\x24\x48\x8B\x8C\x24\x88\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\x0F\xBE\x00\x48\x8B\x0C\x24\x48\x8B\x54\x24\x28\x48\x03\xD1\x48\x8B\xCA\x0F\xBE\x09\x3B\xC1\x74\x02\xEB\x02\xEB\x97\x48\x8B\x04\x24\x48\x8B\x8C\x24\x88\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\x0F\xBE\x00\x85\xC0\x75\x2D\x48\x8B\x04\x24\x48\x8B\x4C\x24\x28\x48\x03\xC8\x48\x8B\xC1\x0F\xBE\x00\x85\xC0\x75\x17\x48\x8B\x44\x24\x60\x8B\x00\x48\x8B\x8C\x24\x80\x00\x00\x00\x48\x03\xC8\x48\x8B\xC1\xEB\x07\xE9\xA0\xFE\xFF\xFF\x33\xC0\x48\x83\xC4\x78\xC3\x48\x89\x4C\x24\x08\x56\x57\x48\x83\xEC\x68\x48\xC7\x44\x24\x30\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x89\x44\x24\x30\x48\x8B\x44\x24\x30\x48\x8B\x40\x18\x48\x89\x44\x24\x38\x48\x8D\x44\x24\x48\x48\x8B\x4C\x24\x38\x48\x8B\xF8\x48\x8D\x71\x10\xB9\x10\x00\x00\x00\xF3\xA4\x48\x8B\x44\x24\x48\x48\x89\x44\x24\x40\x48\x8B\x44\x24\x40\x48\x89\x44\x24\x20\x48\x83\x7C\x24\x20\x00\x0F\x84\xC6\x01\x00\x00\x48\x8B\x44\x24\x20\x48\x83\x78\x30\x00\x0F\x84\xB6\x01\x00\x00\x48\x8B\x44\x24\x20\x48\x83\x78\x60\x00\x75\x02\xEB\xD6\x48\x8B\x44\x24\x20\x48\x8B\x40\x60\x48\x89\x44\x24\x18\x48\xC7\x04\x24\x00\x00\x00\x00\x48\xC7\x04\x24\x00\x00\x00\x00\xEB\x0B\x48\x8B\x04\x24\x48\xFF\xC0\x48\x89\x04\x24\x48\x8B\x84\x24\x80\x00\x00\x00\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x85\xC0\x0F\x84\x23\x01\x00\x00\x48\x8B\x44\x24\x18\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x85\xC0\x0F\x84\x0E\x01\x00\x00\x48\x8B\x84\x24\x80\x00\x00\x00\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x83\xF8\x5A\x7F\x50\x48\x8B\x84\x24\x80\x00\x00\x00\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x83\xF8\x41\x7C\x3B\x48\x8B\x84\x24\x80\x00\x00\x00\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x83\xE8\x41\x83\xC0\x61\x89\x44\x24\x28\x48\x8B\x84\x24\x80\x00\x00\x00\x48\x8B\x0C\x24\x0F\xB7\x54\x24\x28\x66\x89\x14\x48\x0F\xB7\x44\x24\x28\x66\x89\x44\x24\x08\xEB\x15\x48\x8B\x84\x24\x80\x00\x00\x00\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x66\x89\x44\x24\x08\x0F\xB7\x44\x24\x08\x66\x89\x44\x24\x0C\x48\x8B\x44\x24\x18\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x83\xF8\x5A\x7F\x47\x48\x8B\x44\x24\x18\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x83\xF8\x41\x7C\x35\x48\x8B\x44\x24\x18\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x83\xE8\x41\x83\xC0\x61\x89\x44\x24\x2C\x48\x8B\x44\x24\x18\x48\x8B\x0C\x24\x0F\xB7\x54\x24\x2C\x66\x89\x14\x48\x0F\xB7\x44\x24\x2C\x66\x89\x44\x24\x0A\xEB\x12\x48\x8B\x44\x24\x18\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x66\x89\x44\x24\x0A\x0F\xB7\x44\x24\x0A\x66\x89\x44\x24\x10\x0F\xB7\x44\x24\x0C\x0F\xB7\x4C\x24\x10\x3B\xC1\x74\x02\xEB\x05\xE9\xBA\xFE\xFF\xFF\x48\x8B\x84\x24\x80\x00\x00\x00\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x85\xC0\x75\x1C\x48\x8B\x44\x24\x18\x48\x8B\x0C\x24\x0F\xB7\x04\x48\x85\xC0\x75\x0B\x48\x8B\x44\x24\x20\x48\x8B\x40\x30\xEB\x14\x48\x8B\x44\x24\x20\x48\x8B\x00\x48\x89\x44\x24\x20\xE9\x2E\xFE\xFF\xFF\x33\xC0\x48\x83\xC4\x68\x5F\x5E\xC3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

// Encrypted with key: wchar_t key[] = "[$faiusne3";
unsigned char shellcode[] = { "\x62\xc0\x97\x30\x3f\xcf\x4c\x3f\xbb\x93\xa3\x83\x54\xe9\x84\x48\x4a\x4a\x15\xc1\x2b\xfa\x00\xe1\xd0\x84\x78\x0b\xc4\x59\x3d\x94\xd5\x46\xc0\xeb\x44\x93\xc4\x8f\x27\x33\xbe\xf6\x12\x9c\xfa\xcf\x3c\x0b\x43\x36\x29\xcd\x13\xee\x2a\x45\x1b\x78\xe4\xbb\x8c\x70\x36\x86\xf7\x46\x30\xc7\xe6\x42\xf1\xdf\xa3\xef\x44\xdb\x1f\x00\x25\xba\x6c\x1c\x43\x79\x69\xb8\x16\xfd\xbf\x2e\xb9\x09\x05\xad\x0e\x5c\xcd\x81\x42\x72\x7b\xd9\x55\x2a\x92\x45\x77\x1c\xfe\xe1\x0e\x11\xa8\x93\xf1\x27\x2a\x1d\xa3\x73\x8c\xca\xc7\x9e\x1b\xf7\x6d\x1a\x5b\x87\xe3\x6e\x70\x95\xff\x29\xcf\xe8\x10\xd3\x24\x5e\xef\x2a\x4f\xeb\x15\x2d\xe7\x90\xbe\x79\x75\x66\xbe\x02\xb2\x6a\x0e\x51\x4e\x04\xcf\x2c\xde\x4a\x4c\xb2\xe4\x4a\xcd\x79\x30\x8f\x4f\xec\x1c\x5c\xde\xa3\xfe\xef\xab\x0b\x62\x13\x3e\x71\xd8\x81\x1c\xf7\xb6\xd0\xdc\x63\x3d\x2b\x9c\x65\xb6\x86\x21\x94\x44\xaf\xf3\x4b\x50\x59\xe8\x08\x54\xcb\xae\xe4\x14\xbc\x67\xd1\x82\xbf\x3c\xbd\x2f\x33\xc1\x4d\x15\x1b\xa5\x5e\x1b\x53\x9b\xc1\xdb\xcc\xf7\xca\x09\x28\x28\x13\x6c\xfc\x80\xf9\xba\x53\xa1\x4b\xd4\xab\x43\x24\xb1\xe6\xea\xbc\x3c\x1e\xb5\x7b\x79\xb4\x7b\xab\x68\x22\xc2\x64\xd1\x11\xdd\x2d\x7e\xd1\x1c\x78\x93\xa2\x55\x05\xc3\xfa\x7f\x29\xa6\xaf\x31\xe9\x0e\xec\xde\x76\xf3\x62\x35\xb1\xfa\xec\xb8\x2f\x8d\x0c\xdc\xd2\x1f\x2b\x88\xe2\x56\xd9\xda\xac\x97\xc9\x18\x1c\x56\xa8\x97\x87\xcd\x4d\x4c\x1b\xf4\x6f\x57\x73\x47\xab\x09\x7d\x89\x4f\xb1\xd3\xcf\x5b\xf3\x02\x98\x3b\x8f\x02\xb7\xd0\xc5\xe8\xba\x77\x8b\x8b\xdf\xfd\x32\xb4\xab\x75\xfc\xc7\x78\xf3\x03\x38\x63\x54\x95\xb5\x7b\x49\xc5\x51\x2c\x13\xf0\x92\x37\x4d\xda\x76\x8c\xf6\xdd\x0e\xa5\x40\xa7\x5e\x64\x13\x2e\xbf\x1c\xfa\xcd\x59\xb8\xd0\xa2\xa6\xba\x90\xbf\x95\xaa\x83\xe0\x92\xf7\xbc\x32\x15\xbd\xc9\xe8\x8f\x47\xc2\x91\x20\xab\x1f\x4e\xdb\x8d\x7c\x9d\x3e\x70\xfe\x2c\x14\x05\x06\xa5\x34\x6b\xdd\x52\xc5\x95\x37\xd7\x03\xee\xb0\xf6\x2c\xfd\x75\x22\x77\x7d\xdf\x54\x8b\xde\xb7\xd4\x5d\x18\xc3\xd9\x7a\xe5\xf0\x17\x87\x81\x59\x7c\x5b\xc4\x6e\xae\xd3\xcd\x77\xcc\x70\xb3\xe2\x94\x2a\xe5\x27\xbf\xa4\x28\xfa\x61\x3b\xa6\x2c\x06\xa4\x3d\xa0\x92\xea\x8f\x1b\x0c\x95\xb3\x41\x9b\xe0\x6f\x72\xef\x50\xed\x62\xa7\x03\x58\xd6\xca\x5e\x2c\x01\x4d\x0d\x61\xff\xd7\xda\x1b\xec\x97\x9e\xd0\x75\xd3\xed\x6f\x10\x11\x01\xb7\x89\x16\xaa\x1b\x39\xe0\x24\xd5\xba\x43\xa5\xb9\x72\xae\x2b\x4e\xce\x6a\x62\x5d\x08\xfe\x93\x9d\xaf\x35\x42\x16\xda\x60\xb4\x52\x72\xef\x0d\x00\x7f\x62\x78\x20\x4d\x80\x33\x18\x30\x6b\xe8\x40\x62\x8a\x47\xd2\x61\xbd\x38\xc4\xcd\x3c\x13\xc1\xb4\xbd\x34\x7f\x55\x8d\xa2\xbc\x87\xa0\xb5\x5a\xa3\x0b\xc8\x19\xb5\x07\x98\x67\x4e\xbc\x04\x24\xc7\xdc\x6e\xf4\xab\x1c\x5f\xbd\x76\x66\x45\x26\xb2\xc1\x85\x50\x58\xec\xbc\xb3\x2d\x53\x39\x7c\x88\x22\x3e\x83\xe8\xb8\x8a\x60\xc1\xf4\x49\x77\x12\xd3\x2f\xb5\x31\xc9\x1a\xc4\x0b\x58\x0d\x87\xba\xe8\x2c\x43\x6f\xf6\xcd\xae\x38\xa1\xf4\xbb\x8a\x66\xa1\x9a\x9b\x28\xce\xc1\x66\x0f\x93\x05\xfa\x31\x3b\xfb\xc1\x26\xd0\x5f\x58\xa9\xfa\x20\x9c\x87\xa9\xfe\x30\xaa\x33\x87\xf5\xca\x3f\x14\x29\x8b\x60\x92\xdf\x6d\x79\x7b\x49\x65\x6c\xec\x63\xe0\xc4\xbb\xb7\xe8\x9f\xe4\x03\x76\x09\x56\xc6\xe3\xda\x23\x3e\x2e\xb0\x98\xb5\xfc\x2a\xeb\x89\xcf\x47\xf5\xb4\x2f\x04\x13\x4b\x45\xdb\x07\x79\x18\xf3\x6d\x3e\x50\x55\x52\x79\x84\x26\x09\x1f\x56\xb2\x2b\x81\xd5\x8b\x16\x71\xc6\x29\x0f\x74\x62\x6b\x33\xd8\x43\x74\x31\x56\x1d\xe2\xe7\x18\x81\x71\x4c\x36\xfa\x86\x5c\xc0\xe7\xd1\xb3\x68\xd5\x0c\x15\x53\x67\xca\xf0\x09\xbd\xc0\x61\x55\xde\xae\xcd\x6b\x90\x89\x74\xb3\x59\xa5\x2c\xa4\x83\x6b\x13\xf6\x12\x69\xd0\xad\xff\x62\xf9\x78\xfe\x36\x35\x5e\xfb\x73\xf3\x92\xda\xf3\xa8\xa5\x33\x47\x8f\xc0\xde\xe4\xe2\x3e\x01\x80\x3c\x45\x66\xea\x8f\x03\xbf\x6e\xdf\x90\x5e\x82\xb3\x41\x47\x3e\x86\x91\x86\x44\x37\xb9\x04\xa5\x03\x88\xd8\xa6\x1f\x70\x99\x04\xd5\x1c\xf2\x70\x38\xd9\xa8\xb9\xbd\x58\x2d\x1f\xc5\xb8\x95\x84\x3e\x47\x1e\xd2\xed\xd9\x4e\x9c\xf6\x4d\x27\x77\x12\x21\xec\x9b\x5a\x1c\x98\xac\xb2\xea\xe9\xff\x91\xe9\xcc\x60\x1d\xa6\x80\x59\xe2\x6a\x40\x31\x36\xd1\x62\x5a\x79\xe4\x6f\xf3\xd2\x17\x11\x2d\x5f\x11\x11\x4d\x2d\xd4\xb7\x83\x1e\x27\x70\x6b\xaa\xf2\xc2\x93\xf1\x30\xa5\x6a\xef\xc3\xbe\x44\x23\x30\x02\x77\x3a\xb9\xc5\x7c\x29\x16\x3c\x4b\x0c\x51\xb8\x33\x1d\x7c\xfc\xa4\xc7\x18\x25\x3a\xa7\x84\xd2\xc2\xef\x67\x0c\x27\xd4\x52\xe2\xdd\xa8\x33\x96\x19\x11\x38\xc1\x4e\xe4\x39\x7b\xa7\x3b\xba\x76\xcd\x56\xf3\xdc\x76\xd2\x15\x98\x09\xd6\x0d\xdf\x8d\xdc\x46\xfc\x99\x9d\x4d\x16\x7d\x72\x13\xb3\x9d\x73\x46\x16\x87\xd7\x4a\x41\xee\xcf\xb2\x7f\xa8\xc1\x5b\xac\x9f\x91\x5b\x42\xd7\x26\xf0\x14\x15\x79\x88\xed\xff\x0b\xf9\x67\x1d\x17\x1e\x3f\x07\x43\x46\x43\x29\x4e\x1c\x1c\xdc\x1c\xe8\xaf\xb8\x05\x5d\xde\x04\x67\x11\xd4\xbf\x5d\x60\x10\xc3\x3c\xb6\x06\x31\xba\x9a\x4a\x96\xdf\x5d\xf4\x74\x0d\x3a\x5f\xd0\x3c\x6e\xe2\xb4\x9b\x74\x47\xd6\x1d\x29\x9e\x60\x2e\x1e\x87\xc8\xa7\x6e\xb0\x0d\x85\xc6\x9f\x50\x55\xe1\x88\xe5\x20\x25\xcb\x8a\xee\xf3\x55\x4c\x34\xdf\xb4\xa7\x45\x1e\xf8\x94\x6c\xf2\x98\x11\xb9\x9d\x4f\xf8\x8e\x49\x15\x76\xa2\x6a\xf8\xfc\x58\x56\xf5\x8f\xc5\xb1\xd1\x4f\x2f\x78\x43\x5f\xce\x86\x8b\x6a\xa3\x92\xb7\x4f\x28\x82\x80\xe0\x08\x59\x69\x4b\x89\x7b\x77\x01\x59\xb3\xd1\xe9\x50\xf2\x9d\x3e\xb4\x82\xa6\x84\x27\x03\x2f\x70\x54\xc4\x13\x66\x2b\x7b\x44\x07\xc1\x7f\xbb\x18\x1f\xc1\xd2\x14\x60\xed\x9f\x0b\x36\x10\x1f\xbf\x6d\x5f\x85\xf6\x9a\xdc\xa7\xf6\x60\xbf\x52\x52\x4d\x31\x8e\xb6\x7f\xce\x4a\xfc\xcd\xd9\xaa\x27\x53\xf6\xf5\x1b\x6a\xaf\x07\xe2\x0e\x61\x97\xd0\x14\x5a\x5b\xe2\xeb\x31\x20\x55\x6c\x01\xdc\x26\x01\xce\xd2\xf2\xc3\xc5\xa1\xe8\xa7\xe2\xb7\x4c\x44\x3c\x45\x42\xe3\x77\x6e\x84\x68\x5a\xee\xa6\xf6\x7c\xe4\xc8\x74\x66\x9b\xb5\x2e\x87\x96\xc8\x3e\x2a\xe0\xb5\xc8\x9f\x97\xeb\xfd\xf9\x11\xf7\x80\x68\xce\x75\x21\x3b\xee\x75\x4b\x11\x23\x2d\xb7\x02\x4a\xe0\xd7\xab\xff\xbf\x9d\x74\x43\x6c\xb7\x6c\x00\xc1\x26\xd1\xd2\x7f\xe3\xca\x7c\x8f\xc9\x41\xba\x9b\x03\xdb\xa8\x46\x6b\x28\x51\x2a\xad\x9d\xd4\xfe\x5f\x43\x4a\x48\x36\xce\x6e\x68\x4e\x42\xf6\x15\x0a\x07\x63\x0c\x8d\x7a\x28\x1e\x3f\xc8\x90\xa5\xf7\x41\xca\x25\x98\xcb\x58\x16\x28\xb4\x21\x89\x4f\xab\x31\x0f\xb3\x02\xb6\x17\x65\x5c\x45\xb9\x5f\x76\x1f\x8b\xcd\xf1\xd1\x55\x6c\xb0\x15\xaf\xed\x90\x85\xbc\x49\x7f\x6a\xa1\xcf\xd1\x4e\xd6\x10\x2a\xc9\xb8\xa4\xab\x65\x83\x3c\x0b\xeb\x93\x62\x7f\x5d\x62\x8c\xa1\x5e\x75\x4f\x70\x4b\x50\xad\x57\xf1\xe2\x15\x10\xbb\x50\xe2\x6e\xe5\x2e\x65\x45\xe6\x7f\xf6\xa5\x15\xac\xe5\xed\xf2\x0d\x66\xc8\x3d\xc9\x5a\x53\x45\xc8\xf0\x41\xfc\x79\x44\x49\x85\x41\xad\xbb\xc4\xcf\x0d\x77\x70\x32\xf3\x60\xdc\xd3\xca\x71\xab\xcd\xa7\xe7\x60\xc4\xfa\xb9\x7e\x66\xfc\x09\x9b\x3d\x3c\xca\x83\xb6\x14\x52\x9e\x65\x0e\x8c\x04\x4d\x24\xbc\x3e\x92\x3f\xd5\x31\x6f\x00\xea\x68\xac\xcc\xbd\xa4\xb3\x67\xa7\xb6\x06\xe0\x79\xd5\xc2\x35\x72\xda\xda\xca\xdb\x1b\xa1\xb2\x8d\xd8\xc1\xe1\xc4\xbc\xc1\xa0\x01\x8b\x98\x06\xc2\x82\x82\x58\x41\x69\x63\xb4\xd4\x18\x3a\xf2\xa1\x88\x88\x9d\x32\x76\xb9\xd3\x7c\xc7\x0e\xb3\xd2\x79\x25\xc8\xfa\xad\x27\x6e\x34\xb5\x33\x2f\xd6\xc7\x28\x3b\xde\x3f\xd5\x48\x55\x69\x66\x5d\x56\x23\xc9\x66\x86\x5f\x00\x41\xc4\x9a\xe9\x33\x73\x2c\x79\xf3\x4a\x84\x24\x5f\xc5\x8c\xe6\x70\xde\x19\xe4\xb6\xe2\xbd\xaa\xcb\x95\x01\x9d\x57\xb6\x8a\x07\x6f\xd9\x32\x46\x69\xf2\x5c\x80\x36\x7b\xc3\xe3\x6b\x87\x88\xa0\xaf\x78\x04\x7c\xf6\x9c\x4c\xc0\xa4\x0a\x9f\x8f\xd5\x6a\xab\x76\x31\xf6\xef\x28\x97\xad\xb5\x1f\xfa\xa4\xe7\xe4\x63\x44\x78\xd7\x7d\x56\x4c\xad\x3e\xd0\xda\x05\xef\xdb\xe5\x2e\xa8\x91\x19\x0b\xee\x18\xf5\x18\xdf\x1c\x77\xa3\x76\xbd\x68\x6a\x76\xf4\x60\x8a\xb6\x3a\x1e\x3c\xc9\xa9\x16\xe6\xec\xe1\xcc\xab\xfe\x88\x45\x26\x24\xc8\x24\x4a\x30\xdf\x72\xa3\x1a\xb5\x0a\x88\x58\x33\xd0\x6b\xf2\xfc\x7c\x0e\x5b\x88\x46\x1e\x16\x02\x33\xef\x22\xd6\x41\x20\xa9\x1d\x29\x83\x70\x82\x73\x0c\x0c\xcb\x8b\xc8\xa8\x4e\x37\x70\x9b\x28\x71\x6d\x9c\x34\x91\xa9\x84\x7f\xdc\x12\x57\xd4\x0b\x7a\x22\x18\x9d\x73\x8a\x72\x50\x18\x7f\x59\xd7\x9c\x88\xfe\xca\x94\x8c\xbc\xb5\x26\x68\xc1\xf0\x68\x74\x66\xec\x56\x64\xe3\x34\xb2\x1b\xe6\x4c\x85\x1c\x92\x4b\xc2\xce\x43\xdd\x0c\x83\x7f\x57\x6b\xa2\x5f\x0d\x30\x17\x55\x32\xff\xda\x11\xd2\x53\x50\x4a\xf7\xdd\xc2\xbd\xb6\xf5\x54\xf5\x5e\xab\x4c\xc9\x02\x2f\x46\x03\xb3\x3e\x7d\x88\xd0\x59\x6d\x3c\x7b\xba\xc9\x9f\x2d\xfd\x98\x35\xef\xce\x77\x44\x01\x3b\x33\xad\x72\xaf\xb3\x87\xc1\x88\x53\x3f\xb9\x2f\xda\x70\xf5\x4b\xea\x31\x6c\xe4\xe0\xae\x37\x97\xf6\x5a\xbe\x6b\x7e\xfd\x1c\x22\x29\x18\x78\xe6\x2f\xca\xb8\xa9\x3e\xd8\xec\xf1\x16\x86\xc0\xde\x15\xa7\x95\xea\x10\xe6\xe8\x0f\xf3\xa7\x83\xef\x53\x10\xd4\x93\xe9\x73\xd4\x5b\x32\x80\x44\x8c\xb5\x4b\x33\x68\xf1\x01\x30\x31\x71\x8e\xb4\xe1\xa7\xd2\x0c\x13\xd9\xa4\xb5\xa6\x97\x57\x11\x40\xa5\xc2\xaf\xb7\x19\x58\x94\x87\x13\xa0\x17\x2c\x39\x0e\xbb\x66\xe6\x39\xbf\x50\xdb\xe7\xe6\x09\x54\xf3\xe6\xd2\x49\x80\x6e\xa0\xb2\x71\xbf\x79\x50\x2f\xb7\xf5\xa4\x2d\x4b\xf0\xa1\xef\xb8\x0e\x17\xa2\xb9\xcd\x49\x79\xdf\x6e\xd2\xc0\xe8\xe8\x35\x8f\x89\x4e\xc0\x6d\xb5\xe4\x58\x38\x25\x1d\xdd\x05\x90\x1f\xb9\xaf\x18\x97\x24\x09\xdd\xa5\x69\x30\x6f\xa3\x9b\x6d\x0c\x1d\xc6\xfa\xbd\x0f\x0b\x81\x7e\xb7\xe0\xcd\x4d\xf6\x9b\xd7\x13\x3d\xe4\xc7\x4b\x7f\xe4\xee\xa5\xbb\x8c\xf9\x11\xbd\x7b\xb3\x67\x1d\x43\x8e\xe5\xb2\xa5\xdf\xe3\xf1\xac\x95\x92\x3c\x5e\x0d\x35\x5c\xf0\xa8\x98\xf0\x2f\xd1\x5b\x5b\xf9\xd4\x2b\x86\x0b\xd6\x19\xcc\xb1\xca\x8a\xf5\x13\xea\xee\xbb\xc2\x14\xcf\xcf\x50\x0e\xa8\x3f\xff\x6b\xcd\x60\x10\xf0\x83\x37\xcd\xca\xbf\xf8\x28\xe1\x9e\x05\x2c\x22\x80\x72\x60\x47\x87\xfa\xd2\x45\x3f\x2f\x1b\xe0\x07\xcf\x20\x89\xcf\x53\x58\xeb\x3e\xad\x5b\x1e\xe9\x06\x1d\x6c\x8e\xa8\x1e\x75\x2d\x2f\xaa\xf4\xf5\xf1\x36\x31\x5d\x88\x87\x3e\xbb\x82\x14\x91\x54\x88\x2a\x21\xbc\x28\x0d\xc4\x25\x2d\x21\x2e\x6f\x75\x5b\xd9\x31\xdf\x25\xf0\x9c\x9c\xd6\xf1\x6b\xb9\xe9\xdf\x84\x0b\xc6\xd3\x76\xa7\xda\x8d\xa5\x94\xb5\xbf\x2b\x06\xa7\xd7\xc2\x3d\xee\xe0\xb4\x80\x58\x4e\xe7\x29\x4c\x44\x22\xf2\x1d\x21\x5c\xba\x14\x6c\xf8\x74\x10\x5d\x69\xf5\x35\x1c\xba\x58\x5f\xd7\x7e\x30\x26\xe7\xce\xc5\x44\x92\x8a\xea\x01\x08\xb0\xce\x42\x1d\xe4\xde\x7b\x05\xd3\x37\x7d\xa0\x60\xfe\x86\x33\x52\x42\xe5\x03\xe1\xe7\xbf\x31\x54\x53\xc5\xef\x50\x8c\x30\x85\x4c\xcd\x3b\x48\xf1\x2e\xe2\x15\xc5\xa7\xb9\x5f\x73\x3e\x3a\x51\xc7\xa8\xba\xf7\xb6\xb4\xc8\xbf\x4b\xa7\xfb\x94\xe4\x27\xd9\x33\xc4\x6b\xb9\x8c\x39\x24\x24\x47\x5f\x05\xab\xc1\xd2\x51\x8d\xdb\x4e\xaa\x6c\x37\x58\x51\x0e\x22\x00\x18\x38\xfc\x1e\xb0\xd4\xa3\xaf\x67\xdd\x99\x68\x98\xbd\x5a\x9f\xb7\xed\xc8\xfe\xe6\xc0\x5c\x01\x60\x17\x5e\x11\x3f\x34\x7b\x80\x31\xa6\x4e\x78\x44\x71\x0d\x4e\x8b\xf4\xab\x80\x4a\x48\x72\x90\x90"};