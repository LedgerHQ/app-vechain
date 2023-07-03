from vechain_client import VechainClient

# Taken from the Makefile, to update every time the Makefile version is bumped
MAJOR = 1
MINOR = 1
PATCH = 1

# multi-clauses and data not allowed by default
DEFAULT_FLAGS_SETTING = 0x00

# In this test we check that the get_configuration replies the right application version and
# right configuration flags
def test_app_configuration(backend):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)
    # Send the get_version instruction to the app
    configuration = client.get_app_configuration()
    # Assert that we have received the correct app version and flag settings
    # are set to default values
    assert configuration == (DEFAULT_FLAGS_SETTING, MAJOR, MINOR, PATCH)
