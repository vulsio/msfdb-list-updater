# initialize was taken from metasploit-framework.
# BSD-3-clause (c) 2006-2020, Rapid7, Inc.
# (https://github.com/rapid7/metasploit-framework/blob/master/LICENSE)

def initialize(info = {})
    super(update_info(info,
        'Name' => 'OpenEMR 5.0.1 Patch 6 SQLi Dump',
        'Description' => '
        This module exploits a SQLi vulnerability found in
        OpenEMR version 5.0.1 Patch 6 and lower. The
        vulnerability allows the contents of the entire
        database (with exception of log and task tables) to be
        extracted.
        This module saves each table as a `.csv` file in your
        loot directory and has been tested with
        OpenEMR 5.0.1 (3).
        ',
        'License' => MSF_LICENSE,
        'Author' =>
        [
            'Will Porter <will.porter[at]lodestonesecurity.com>'
        ],
        'References' => [
        ['CVE', '2018-17179'],
        ['URL', 'https://github.com/openemr/openemr/commit/3e22d11c7175c1ebbf3d862545ce6fee18f70617']
        ],
        'DisclosureDate' => 'May 17 2019'
    ))

    register_options(
        [
        OptString.new('TARGETURI', [true, 'The base path to the OpenEMR installation', '/openemr'])
        ]
    )
end