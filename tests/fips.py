try:
    f = open('/proc/sys/crypto/fips_enabled')
    try:
        fips_mode = int(f.read())
    finally:
        f.close()
except Exception as e:
    fips_mode = 0
