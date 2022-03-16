# PkcsInfo

[![MSBuild](https://github.com/alexyack/PkcsInfo/actions/workflows/msbuild.yml/badge.svg)](https://github.com/alexyack/PkcsInfo/actions/workflows/msbuild.yml)

PKCS#11 info tool

Lists all slots and tokens.
For slots with inserted tokens list all mechanisms and objects.

## Using
`pkcsinfo.exe [<module name> [<slot name> [<user pin>]]]`

if no parameters specified - simple call using `jcpkcs11-2.dll`, list all slots, public objects only. 

`<module name>` - call using specific PKCS#11 module (`etpkcs11.dll` for example for Aladdin eToken). 

`<slot name>` - print information about properties and objects only in specified slot (for examle `"Athena ASEDrive IIIe USB 0"`)

`<user pin>` - try to logon (using `C_Login(CKU_USER)`) and print properties for private objects too.
