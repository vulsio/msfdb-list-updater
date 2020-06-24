def initialize(info = {})
  super(
    update_info(
      info,
      # The Name should be just like the line of a Git commit - software name,
      # vuln type, class. Preferably apply
      # some search optimization so people can actually find the module.
      # We encourage consistency between module name and file name.
      'Name'           => 'Sample Exploit',
      'Description'    => %q(
          This exploit module illustrates how a vulnerability could be exploited
        in an TCP server that has a parsing bug.
      ),
      'License'        => MSF_LICENSE,
      'Author'         => ['John Doe'],
      'References'     =>
        [
          [ 'OSVDB', '12345' ],
          [ 'EDB', '12345' ],
          [ 'URL', 'http://www.example.com'],
          [ 'CVE', '1978-1234']
          [ 'CVE', '1978-5678']
          [ 'CWE', '123']
          [ 'BID', '12345']
          [ 'ZDI', '12-345']
          [ 'MSB', 'MS12-345']
          [ 'WPVDB', '12345']
          [ 'US-CERT-VU', '12345']
          [ 'PACKETSTORM', '12345']
        ],
      'Payload'        =>
        {
          'Space'    => 1000,
          'BadChars' => "\x00"
        },
      'Targets'        =>
        [
          # Target 0: Windows All
          [
            'Windows XP/Vista/7/8',
            {
              'Platform' => 'win',
              'Ret'      => 0x41424344
            }
          ]
        ],
      'DisclosureDate' => "Apr 1 2013",
      # Note that DefaultTarget refers to the index of an item in Targets, rather than name.
      # It's generally easiest just to put the default at the beginning of the list and skip this
      # entirely.
      'DefaultTarget'  => 0
    )
  )
end