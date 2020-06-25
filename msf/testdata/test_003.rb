# initialize was taken from metasploit-framework.
# BSD-3-clause (c) 2006-2020, Rapid7, Inc.
# (https://github.com/rapid7/metasploit-framework/blob/master/LICENSE)

def initialize(info={})
    super( update_info( info, {
        'Name'          => "Android Binder Use-After-Free Exploit",
        'Description'   => %q{
            This module exploits CVE-2019-2215, which is a use-after-free in Binder in the
            Android kernel. The bug is a local privilege escalation vulnerability that
            allows for a full compromise of a vulnerable device. If chained with a browser
            renderer exploit, this bug could fully compromise a device through a malicious
            website.
            The freed memory is replaced with an iovec structure in order to leak a pointer
            to the task_struct. Finally the bug is triggered again in order to overwrite
            the addr_limit, making all memory (including kernel memory) accessible as part
            of the user-space memory range in our process and allowing arbitrary reading
            and writing of kernel memory.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
            'Jann Horn',    # discovery and exploit
            'Maddie Stone', # discovery and exploit
            'grant-h',      # Qu1ckR00t
            'timwr',        # metasploit module
        ],
        'References'    => [
            [ 'CVE', '2019-2215' ],
            [ 'URL', 'https://bugs.chromium.org/p/project-zero/issues/detail?id=1942' ],
            [ 'URL', 'https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html' ],
            [ 'URL', 'https://hernan.de/blog/2019/10/15/tailoring-cve-2019-2215-to-achieve-root/' ],
            [ 'URL', 'https://github.com/grant-h/qu1ckr00t/blob/master/native/poc.c' ],
        ],
        'DisclosureDate' => "Sep 26 2019",
        'SessionTypes'   => [ 'meterpreter' ],
        'Platform'       => [ "android", "linux" ],
        'Arch'           => [ ARCH_AARCH64 ],
        'Targets'        => [[ 'Auto', {} ]],
        'DefaultOptions' =>
        {
            'PAYLOAD'      => 'linux/aarch64/meterpreter/reverse_tcp',
            'WfsDelay'     => 5,
        },
        'DefaultTarget' => 0,
        }
    ))
end