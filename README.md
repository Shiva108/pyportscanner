# pyportscanner
> Network / Port scanner written in python 3.5 with banner grab

## How to setup

1. Make sure you have python installed.
2. Install python-nmap library ( other libraries should be installed by default ).

`pip install python-nmap`

## Executing

Windows & Linux:

```
python Fportscan.py host start_port end_port udpscan
```
host - Target host that should be scanned

start_port - Start scanning from this port

end_port - Scan until this port

udpscan - Enable this for UDP scans

## Contributing

1. Fork it (<https://github.com/Shiva108/pyportscanner/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
