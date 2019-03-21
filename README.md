# 7402-ass5

## usage

```
usage:
    ./feistel.py [function] [mode] [quality] [input filename] [output filename]
            function is 'e' for encrypt, 'd' for decrypt
            mode is 'ecb' for ecb, 'cbc' for cbc, and 'ctr' for ctr
            quality is 'e' for easy, 'm' for medium, 'h' for hard

    ./feistel.py t [input filename]
            runs automated tests to compare the different modes using a given file
```