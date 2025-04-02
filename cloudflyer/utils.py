def get_free_port(host='127.0.0.1'):
    """
    Get an available free port on the specified IP address
    
    Args:
        ip (str): IP address, defaults to localhost '127.0.0.1'
        
    Returns:
        int: Available port number
    """
    import socket
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Set port to 0 to let the system assign a random free port
        sock.bind((host, 0))
        # Get the assigned port number
        _, port = sock.getsockname()
        return port
    finally:
        sock.close()
