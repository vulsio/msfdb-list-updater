def initialize(info = {})
    super(
        update_info(
        info,
        'Name'           => 'Sample Auxiliary',
        # The description can be multiple lines, but does not preserve formatting.
        'Description'    => 'Sample Auxiliary Module',
        'Author'         => ['Joe Module <joem@example.com>'],
        'License'        => MSF_LICENSE,
        'Actions'        => [
            [ 'Default Action', 'Description' => 'This does something' ],
            [ 'Another Action', 'Description' => 'This does a different thing' ]
        ],
        # The action(s) that will run as background job
        'PassiveActions' => [
            'Another Action'
        ],
        'DefaultAction'  => 'Default Action'
        )
    )
end
