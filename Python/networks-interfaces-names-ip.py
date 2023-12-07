import socket
import fcntl
import struct

class Networks:
    """Classe responsável por obter informações das interfaces de rede."""

    def __init__(self):
        pass

    @staticmethod
    def get_network_interfaces():
        """Retorna um dicionário contendo o nome, o endereço IP e a máscara de rede das interfaces de rede ativas.

        Returns:
            dict: dicionário onde a chave é o nome da interface e o valor é o IP e a máscara
        """
        interfaces = socket.if_nameindex()
        result = dict()

        for index, interface_name in interfaces:
            ip_address = Networks.get_interface_ip(interface_name)
            netmask = Networks.get_interface_netmask(interface_name)
            
            if ip_address and netmask:
                result[interface_name] = (ip_address, netmask)

        del result['lo']
        return result

    @staticmethod
    def get_interface_ip(interface):
        """Retorna o endereço IP pelo nome da interface fornecida.

        Args:
            interface (str): Nome da interface de rede.

        Returns:
            str: endereço IP da interface
        """

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_address = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface[:15].encode())
            )[20:24])
            return ip_address
        except IOError:
            return None

    @staticmethod    
    def get_interface_netmask(interface):
        """Retorna a máscara de rede pelo nome da interface fornecida.

        Args:
            interface (str): Nome da interface de rede.

        Returns:
            str: máscara de rede da interface
        """
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            netmask = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x891b,  # SIOCGIFNETMASK
                struct.pack('256s', interface[:15].encode())
            )[20:24])
            return netmask
        except IOError:
            return None
        

if __name__ == '__main__':
    print(Networks.get_network_interfaces())