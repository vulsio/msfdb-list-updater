def initialize(info = {})
  super(
    update_info(
      info,
      'Name'           => 'Sample Module',
      'License'        => MSF_LICENSE,
      'Author'         => ['John Doe'],
      'DisclosureDate' => "Apr 1 2999",
    )
  )
end