class ELBCertificate(object):
    """Support for amazon's classic load-balancers"""
    
    def __init__(self, elb_client, iam_client, elb_name, elb_port, logger):
        self.elb_client = elb_client
        self.iam_client = iam_client
        self.elb_name = elb_name
        self.elb_port = elb_port
        self.logger = logger

    def get_iam_certificate(self, certificate_id):
	paginator = self.iam_client.get_paginator("list_server_certificates")
	for page in paginator.paginate():
	    for server_certificate in page["ServerCertificateMetadataList"]:
		if server_certificate["Arn"] == certificate_id:
		    cert_name = server_certificate["ServerCertificateName"]
		    response = self.iam_client.get_server_certificate(
			ServerCertificateName=cert_name,
		    )
		    return x509.load_pem_x509_certificate(
			response["ServerCertificate"]["CertificateBody"].encode(),
			default_backend(),
		    )

    def get_current_certificate(self):
        response = self.elb_client.describe_load_balancers(
            LoadBalancerNames=[self.elb_name]
        )
        [description] = response["LoadBalancerDescriptions"]
        [elb_listener] = [
            listener["Listener"]
            for listener in description["ListenerDescriptions"]
            if listener["Listener"]["LoadBalancerPort"] == self.elb_port
        ]

        if "SSLCertificateId" not in elb_listener:
            raise ValueError(
                "A certificate must already be configured for the ELB"
            )

        return self.get_iam_certificate(
            elb_listener["SSLCertificateId"]
        )

    def update_certificate(self, hosts, private_key, pem_certificate,
                           pem_certificate_chain):
        self.logger.emit(
            "updating-elb.upload-iam-certificate", elb_name=self.elb_name
        )

        response = self.iam_client.upload_server_certificate(
            ServerCertificateName=generate_certificate_name(
                hosts,
                x509.load_pem_x509_certificate(
                    pem_certificate, default_backend()
                )
            ),
            PrivateKey=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            CertificateBody=pem_certificate.decode(),
            CertificateChain=pem_certificate_chain.decode(),
        )
        new_cert_arn = response["ServerCertificateMetadata"]["Arn"]

        # Sleep before trying to set the certificate, it appears to sometimes
        # fail without this.
        time.sleep(15)
        self.logger.emit("updating-elb.set-elb-certificate", elb_name=self.elb_name)
        
        response = self.elb_client.describe_load_balancers(
            LoadBalancerNames=[self.elb_name]
        )
        
        self.elb_client.set_load_balancer_listener_ssl_certificate(
            LoadBalancerName=self.elb_name,
            SSLCertificateId=new_cert_arn,
            LoadBalancerPort=self.elb_port,
        )

class ELBCertificateElbV2(ELBCertificate):
    """Support for amazon's application loadbalancers (ELB-API V2)"""

    def __init__(self, elb_client, iam_client, elb_name, elb_port, logger):
        super(ELBCertificateElbV2, self).__init__(elb_client, iam_client, elb_name, elb_port, logger)        

    def get_current_certificate(self):
        response = self.elb_client.describe_load_balancers(
            Names=[self.elb_name]
        )
        elb_listener = []
        for dsc in response["LoadBalancers"]:
            targets = self.elb_client.describe_listeners(
                LoadBalancerArn=dsc["LoadBalancerArn"]
            )
            self.logger.emit(
                "ELBCertificateElbV2.get_current_certificate: Collecting targets", 
                targets=targets)
            [elb_listener] = [
                listener
                for listener in targets["Listeners"]
                if listener["Port"] == self.elb_port
            ]

        if "Certificates" not in elb_listener:
            raise ValueError(
                "A certificate must already be configured for the ELB"
            )
	cert_arn = elb_listener["Certificates"][0]["CertificateArn"]
        self.logger.emit( "elb_listeners/certificates", certs=cert_arn)
        return self.get_iam_certificate( cert_arn )

    def update_certificate(self, hosts, private_key, pem_certificate,
                           pem_certificate_chain):
        self.logger.emit(
            "ELBCertificateElbV2.updating-elb.upload-iam-certificate", elb_name=self.elb_name
        )

        response = self.iam_client.upload_server_certificate(
            ServerCertificateName=generate_certificate_name(
                hosts,
                x509.load_pem_x509_certificate(
                    pem_certificate, default_backend()
                )
            ),
            PrivateKey=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            CertificateBody=pem_certificate.decode(),
            CertificateChain=pem_certificate_chain.decode(),
        )
        new_cert_arn = response["ServerCertificateMetadata"]["Arn"]

        # Sleep before trying to set the certificate, it appears to sometimes
        # fail without this.
        time.sleep(15)
        self.logger.emit("updating-elb.set-elb-certificate", elb_name=self.elb_name)
        
        response = self.elb_client.describe_load_balancers(
            LoadBalancerNames=[self.elb_name]
        )
        
        self.elb_client.set_load_balancer_listener_ssl_certificate(
            LoadBalancerName=self.elb_name,
            SSLCertificateId=new_cert_arn,
            LoadBalancerPort=self.elb_port,
        )

