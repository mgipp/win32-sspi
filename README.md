This project is a fork of djbergers win32-sspi project which provided an FFI
implementation of SSPI on Windows. This project adds support for Kerberos
through the SPNEGO/Negotiate protocol.

The examples directory has two working examples to illustrate usage.
The sspi_ntlm_*.rb files are a client/server examples that use djbergers
original client/server implementations for NTLM.

The sspi_negotiate_*.rb files are client/server examples of using
Kerberos through SPNEGO/Negotiate protocol. In order to be used successfully across
multiple systems in your domain you must define a Service Principal Name (SPN) 
associated with the user account under which the server is running unless the server
is running as a Windows Service under the LocalSystem account. To establish a SPN
use the setspn command as follows from a elevated privilege command window:

  setspn -S HTTP/fqdn-of-your-host USERDOMAIN\USERNAME

The negotiate client/server implementations are also capable of supporting the NTLM protocol.
