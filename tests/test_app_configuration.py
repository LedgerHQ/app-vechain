from vechain_client import VechainClient
from utils import verify_version

# multi-clauses and data not allowed by default
# DEFAULT_FLAGS_SETTING = 0x03
DEFAULT_FLAGS_SETTING = 0x00


# In this test we check that the get_configuration replies the right application version and
# right configuration flags
def test_app_configuration(backend):
    # Use the app interface instead of raw interface
    client = VechainClient(backend)
    # Send the get_version instruction to the app
    configuration = client.get_app_configuration()
    # Assert that we have received the correct app version and flag settings
    assert configuration[0] == DEFAULT_FLAGS_SETTING
    verify_version(f"{configuration[1]}.{configuration[2]}.{configuration[3]}")
