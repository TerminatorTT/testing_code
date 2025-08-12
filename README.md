firewall_endpoints = {
  # "fwes-npd-usc1a-01-jumbo" = {
  #   name               = "fwes-npd-usc1a-01-jumbo"
  #   parent             = "organizations/583263843096"
  #   location           = "us-central1-a"
  #   billing_project_id = "prj-vcrp-netinfra-n01"
  #   labels = {
  #     fwp-override-backend = "jumbo-frames-enabled"
  #   }
  #   fw_ep_associations = {
  #     "vpc-gnc-am-a-gked-01" = {
  #       fw_ip_association_parent   = "projects/prj-vcrp-netinfra-n01"
  #       network                    = "projects/prj-vcrp-netinfra-n01/global/networks/vpc-gnc-am-a-gked-01"
  #       fw_ip_association_location = "us-central1-a"
  #       fw_ep_association_labels   = {}
  #       tls_inspection_policy      = null
  #       disabled                   = false
  #     },
  #   }
  # },
}

hierarchical_fw_policies = {
  "fwhf-pol-npd-01" = {
    short_name  = "fwhf-pol-npd-01"
    description = "Hierarchical Firewall Policy Non Prod 01"
    parent      = "folders/501103213000"
    fw_policy_associations = {
      "fwhf-pol-npd-01-assoc-nw-non-prod" = {
        association_name  = "fwhf-pol-npd-01-assoc-nw-non-prod"
        attachment_target = "folders/501103213000"
      },
    }
    fw_policy_rules = {

      "10001" = { # Deny known malicious IPs egress traffic #
        priority                = 10001
        direction               = "EGRESS"
        action                  = "deny"
        rule_name               = "10001"
        disabled                = false
        description             = "Deny known malicious IPs egress traffic"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          dest_threat_intelligences = ["iplist-known-malicious-ips", "iplist-crypto-miners", "iplist-vpn-providers", "iplist-tor-exit-nodes", "iplist-anon-proxies"]
          src_ip_ranges             = ["100.126.0.0/16"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "10002" = { # Deny sanctioned countries ingress traffic #
        priority                = 10002
        direction               = "INGRESS"
        action                  = "deny"
        rule_name               = "10002"
        disabled                = false
        description             = "Deny sanctioned countries ingress traffic"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_region_codes = ["IQ", "IR", "KP", "KZ", "RU", "SY", "BD", "BB", "BO", "IS", "NG", "CI", "MN", "PW", "SO", "YE", "BY"]
          dest_ip_ranges   = ["100.126.0.0/16"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "10003" = { # Deny sanctioned countries Egress traffic #
        priority                = 10003
        direction               = "EGRESS"
        action                  = "deny"
        rule_name               = "10003"
        disabled                = false
        description             = "Deny sanctioned countries Egress traffic"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          dest_region_codes = ["IQ", "IR", "KP", "KZ", "RU", "SY", "BD", "BB", "BO", "IS", "NG", "CI", "MN", "PW", "SO", "YE", "BY"]
          src_ip_ranges     = ["100.126.0.0/16"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "10500" = { # [Exception] - Allow Prod and Non-Prod DC communication #
        priority                = 10500
        direction               = "EGRESS"
        action                  = "allow"
        rule_name               = "10500"
        disabled                = false
        description             = "[Exception] - Allow Prod and Non-Prod DC communication"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges = [
            "100.126.1.10/32",
            "100.126.1.26/32",
            "100.126.129.10/32",
            "100.126.129.26/32",
            "100.126.193.10/32",
            "100.126.193.26/32"
          ]
          dest_ip_ranges = [
            "100.125.1.10/32",
            "100.125.1.11/32",
            "100.125.1.26/32",
            "100.125.129.10/32",
            "100.125.129.11/32",
            "100.125.129.26/32",
            "100.125.193.10/32",
            "100.125.193.11/32",
            "100.125.193.26/32"
          ]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "10501" = { # [Exception] - Allow Prod and Non-Prod DC communication #
        priority                = 10501
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "10501"
        disabled                = false
        description             = "[Exception] - Allow Prod and Non-Prod DC communication"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges = [
            "100.125.1.10/32",
            "100.125.1.11/32",
            "100.125.1.26/32",
            "100.125.129.10/32",
            "100.125.129.11/32",
            "100.125.129.26/32",
            "100.125.193.10/32",
            "100.125.193.11/32",
            "100.125.193.26/32"
          ]
          dest_ip_ranges = [
            "100.126.1.10/32",
            "100.126.1.26/32",
            "100.126.129.10/32",
            "100.126.129.26/32",
            "100.126.193.10/32",
            "100.126.193.26/32"
          ]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "10502" = { # [Exception] - RITM11959710 - APP2003759 - Allow Proxy Subnets to communicate within Pelican VMs #
        priority                = 10502
        action                  = "allow"
        direction               = "EGRESS"
        description             = "[Exception] - RITM11959710 - APP2003759 - Allow Proxy Subnets to communicate within Pelican VMs"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges = [
            "100.126.3.128/25",
            "100.126.132.0/26"
          ]
          dest_ip_ranges = [
            "100.126.3.20/32",
            "100.126.131.162/32"
          ]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["8080"]
            },
          ]
        }
      },
      "10503" = { # [Exception] - RITM11959710 - APP2003759 - Allow Proxy Subnets to communicate within Pelican VMs #
        priority                = 10503
        action                  = "allow"
        direction               = "INGRESS"
        description             = "[Exception] - RITM11959710 - APP2003759 - Allow Proxy Subnets to communicate within Pelican VMs"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges = [
            "100.126.3.128/25",
            "100.126.132.0/26"
          ]
          dest_ip_ranges = [
            "100.126.3.20/32",
            "100.126.131.162/32"
          ]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["8080"]
            },
          ]
        }
      },
      "19998" = { # Deny communications from Non-Prod to Prod environments #
        priority                = 19998
        direction               = "EGRESS"
        action                  = "deny"
        rule_name               = "19998"
        disabled                = false
        description             = "Deny communications from Non-Prod to Prod environments"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges  = ["100.126.0.0/16"]
          dest_ip_ranges = ["100.125.0.0/16"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "19999" = { # Deny communications from Prod to Non-Prod environments #
        priority                = 19999
        direction               = "INGRESS"
        action                  = "deny"
        rule_name               = "19999"
        disabled                = false
        description             = "Deny communications from Prod to Non-Prod environments"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges  = ["100.125.0.0/16"]
          dest_ip_ranges = ["100.126.0.0/16"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "20000" = { # Defer Inter-VPC/Intra-VPC firewalling to Global Network Firewall rules with “goto_next” action #
        priority                = 20000
        direction               = "EGRESS"
        action                  = "goto_next"
        rule_name               = "20000"
        disabled                = false
        description             = "Defer Inter-VPC/Intra-VPC firewalling to Global Network Firewall rules with “goto_next” action"
        enable_logging          = false
        target_service_accounts = []
        target_resources        = []
        match = {
          # TODO: Clean up 10.255.101.0/24, 10.255.102.0/24 when testing is done, Partha is PoC.
          src_ip_ranges  = ["100.126.0.0/16", "192.168.128.0/17", "198.18.0.0/17", "10.255.101.0/24", "10.255.102.0/24", "240.0.0.0/5"]
          dest_ip_ranges = ["100.126.0.0/16", "192.168.128.0/17", "198.18.0.0/17", "10.255.101.0/24", "10.255.102.0/24", "240.0.0.0/5"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "20001" = { # Defer Inter-VPC/Intra-VPC, CCI traffic firewalling to Global Network Firewall rules with “goto_next” action #
        priority                = 20001
        direction               = "INGRESS"
        action                  = "goto_next"
        rule_name               = "20001"
        disabled                = false
        description             = "Defer Inter-VPC/Intra-VPC, CCI traffic firewalling to Global Network Firewall rules with “goto_next” action"
        enable_logging          = false
        target_service_accounts = []
        target_resources        = []
        match = {
          # TODO: Clean up 10.255.101.0/24, 10.255.102.0/24 when testing is done, Partha is PoC.
          src_ip_ranges  = ["100.126.0.0/16", "192.168.128.0/17", "198.18.0.0/17", "10.255.101.0/24", "10.255.102.0/24", "240.0.0.0/5"]
          dest_ip_ranges = ["100.126.0.0/16", "192.168.128.0/17", "198.18.0.0/17", "10.255.101.0/24", "10.255.102.0/24", "240.0.0.0/5"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "20002" = { // [Exception] - RITM11923149 - Egress for APP2003759 Pelican VMs to AWS
        priority                = 20002
        direction               = "EGRESS"
        action                  = "allow"
        rule_name               = "20002"
        disabled                = false
        description             = "[Exception] - RITM11923149 - Egress for APP2003759 Pelican VMs to AWS"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["100.126.3.19/32", "100.126.3.20/32"]
          dest_ip_ranges = ["100.127.3.0/24"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["1433", "5439"]
            },
          ]
        }
      },
      "30000" = { # GCP to On-prem. 3 Tuple rule. (Rule to avoid fragmantation) #
        priority                = 30000
        direction               = "EGRESS"
        action                  = "allow"
        rule_name               = "30000"
        disabled                = false
        description             = "GCP to On-prem. 3 Tuple rule. (Rule to avoid fragmantation)"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges       = ["100.126.0.0/16"]
          dest_address_groups = ["organizations/583263843096/locations/global/addressGroups/grp-mcd-onprem-prefixes"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "30001" = { # On-prem to GCP. 3 Tuple rule. (Rule to avoid fragmantation) #
        priority                = 30001
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "30001"
        disabled                = false
        description             = "On-prem to GCP. 3 Tuple rule. (Rule to avoid fragmantation)"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_address_groups = ["organizations/583263843096/locations/global/addressGroups/grp-mcd-onprem-prefixes"]
          dest_ip_ranges     = ["100.126.0.0/16"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      ## 100000-129998 - Are exceptions rules which allow internet to known destination and not performing L7 inspection.
      ## Before matching catch all on 129999
      "100000" = { # Allow APP2003759 Pelican Hosts IAP Access #
        priority                = 100000
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "100000"
        disabled                = false
        description             = "[Exception] - Allow APP2003759 Pelican Hosts IAP Access"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          # TODO: Replace destination IPs with Secure tags
          src_ip_ranges  = ["35.235.240.0/20"]
          dest_ip_ranges = ["100.126.3.0/25", "100.126.131.160/27"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["22", "3000", "5601", "8080"]
            },
          ]
        }
      },
      "100001" = { # Allow Cloud DNS Forwarder TCP/UDP Ingress to DNS/DCs #
        priority                = 100001
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "100001"
        disabled                = false
        description             = "[Exception] - Allow Cloud DNS Forwarder TCP/UDP Ingress to DNS/DCs"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        security_profile_group  = ""
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["35.199.192.0/19"]
          dest_ip_ranges = ["100.126.1.0/28", "100.126.1.16/28", "100.126.193.16/28", "100.126.193.0/28", "100.126.129.0/28", "100.126.129.16/28"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["53"]
            },
            {
              ip_protocol = "udp"
              ports       = ["53"]
            },
          ]
        }
      },
      "100002" = { # [3PFW] - Loadbalancer Health Check to Communicate to loopback IP #
        priority                = 100002
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "100002"
        disabled                = false
        description             = "[Exception] - Allow GCP Loadbalancer Health Check Ranges to NPD Non-Routable Ranges"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges = [
            "35.191.0.0/16",
            "130.211.0.0/22",
            "209.85.152.0/22",
            "209.85.204.0/22"
          ]
          dest_ip_ranges = [
            "192.168.255.224/28",
            "198.18.0.0/17",
            "240.0.0.0/5"
          ]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["80", "443", "667", "1883", "8080", "8443", "15021"]
            },
          ]
        }
      },
      "100003" = { # Loadbalancer Health Check for Serverless VPC Connector Range #
        priority                = 100003
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "100003"
        disabled                = false
        description             = "[Exception] - Allow GCP Loadbalancer Health Check Range for Serverless VPC Connector Range"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["35.199.224.0/19"]
          dest_ip_ranges = ["192.168.255.224/28"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["667"]
            },
            {
              ip_protocol = "udp"
              ports       = ["665-666"]
            },
            {
              ip_protocol = "icmp"
              ports       = []
            },
          ]
        }
      },
      "100004" = { # GCP Loadbalancer Health Check to Communicate with Routable hosts #
        priority                = 100004
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "100004"
        disabled                = false
        description             = "[Exception] - Allow GCP Loadbalancer Health Check Ranges to Routable hosts"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges = [
            "35.191.0.0/16",
            "130.211.0.0/22"
          ]
          dest_ip_ranges = [
            "100.126.3.20/32",
            "100.126.131.162/32"
          ]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["8080"]
            },
          ]
        }
      },
      "129997" = { # Catch all Internet Ingress for L7 Inspection - Americas  #
        priority                = 129997
        direction               = "INGRESS"
        action                  = "apply_security_profile_group"
        security_profile_group  = "//networksecurity.googleapis.com/organizations/583263843096/locations/global/securityProfileGroups/grp-vfw-am-npd-custom"
        rule_name               = "129997"
        disabled                = false
        description             = "Catch all Internet Ingress for L7 Inspection - Americas"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["0.0.0.0/0"]
          dest_ip_ranges = ["100.126.0.0/17"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "129998" = { # Catch all Internet Ingress for L7 Inspection - Asia Pacific  #
        priority                = 129998
        direction               = "INGRESS"
        action                  = "apply_security_profile_group"
        security_profile_group  = "//networksecurity.googleapis.com/organizations/583263843096/locations/global/securityProfileGroups/grp-vfw-ap-npd-custom"
        rule_name               = "129998"
        disabled                = false
        description             = "Catch all Internet Ingress for L7 Inspection - Asia Pacific"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["0.0.0.0/0"]
          dest_ip_ranges = ["100.126.192.0/18"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "129999" = { # Catch all Internet Ingress for L7 Inspection - Europe  #
        priority                = 129999
        direction               = "INGRESS"
        action                  = "apply_security_profile_group"
        security_profile_group  = "//networksecurity.googleapis.com/organizations/583263843096/locations/global/securityProfileGroups/grp-vfw-eu-npd-custom"
        rule_name               = "129999"
        disabled                = false
        description             = "Catch all Internet Ingress for L7 Inspection - Europe"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["0.0.0.0/0"]
          dest_ip_ranges = ["100.126.128.0/18"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "120001" = { # Allow Traffic for IAP TCP 22 #
        priority                = 120001
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "120001"
        disabled                = false
        description             = "Allow Traffic for IAP TCP 22"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges = ["35.235.240.0/20"]
          dest_ip_ranges = [
            "100.126.193.26/32", # DC VM
            "100.126.193.10/32", # DC VM
            "100.126.129.10/32", # DC VM
            "100.126.129.26/32", # DC VM
            "100.126.1.10/32",   # DC VM
            "100.126.1.26/32",   # DC VM
            "100.126.2.32/27",   # CSEC
            "100.126.2.0/29",    # DNS VM
            "100.126.2.192/28",  # GTIO DEV
            "100.126.2.240/28",  # GSOC DEV
            "198.18.5.32/27",    # GTIO OPS
            "198.18.9.0/24"      # SLCP Boost   
          ]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["22"]
            },
          ]
        }
      },
      "120002" = { # Allow Traffic for IAP TCP 3389 #
        priority                = 120002
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "120002"
        disabled                = false
        description             = "Allow Traffic for IAP TCP 3389"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges = ["35.235.240.0/20"]
          dest_ip_ranges = [
            "100.126.193.26/32", # DC VM
            "100.126.193.10/32", # DC VM
            "100.126.129.10/32", # DC VM
            "100.126.129.26/32", # DC VM
            "100.126.1.10/32",   # DC VM
            "100.126.1.26/32",   # DC VM
            "100.126.2.32/27",   # CSEC
            "100.126.2.0/29",    # DNS VM
            "198.18.9.0/24"      # SLCP Boost
          ]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["3389"]
            },
          ]
        }
      },
      "120003" = { # Allow Traffic for IAP (Defer to Global Firewall - Secure Tag not available) #
        priority                = 120003
        direction               = "INGRESS"
        action                  = "allow"
        rule_name               = "120003"
        disabled                = false
        description             = "APP2003540 - Allow for IAP on Custom Ports to SLCP Boost"
        enable_logging          = false
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["35.235.240.0/20"]
          dest_ip_ranges = ["198.18.9.0/24"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["8001", "8088", "8123", "9900"]
            },
          ]
        }
      },
      "120020" = { # Allow Traffic for IAP (Defer to Global Firewall - Secure Tag not available) #
        priority                = 120020
        direction               = "INGRESS"
        action                  = "goto_next"
        rule_name               = "120020"
        disabled                = false
        description             = "Allow Traffic for IAP (Defer to Global Firewall - Secure Tag not available)"
        enable_logging          = false
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["35.235.240.0/20"]
          dest_ip_ranges = ["100.126.0.0/16", "10.255.101.0/24", "10.255.102.0/24", "198.18.0.0/17"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["22", "3389"]
            },
          ]
        }
      },
      "129990" = { # Global Ingress - DevOps Argo UI #
        priority                = 129990
        direction               = "INGRESS"
        action                  = "apply_security_profile_group"
        security_profile_group  = "//networksecurity.googleapis.com/organizations/583263843096/locations/global/securityProfileGroups/grp-vfw-am-npd-custom"
        rule_name               = "129990"
        disabled                = false
        description             = "Allow DevOps Ingress for Argo UI"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["0.0.0.0/0"]
          dest_ip_ranges = ["34.10.15.93/32"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["443"]
            },
          ]
        }
      },
      "130011" = { # Global Egress - Windows KMS traffic #
        priority                = 130011
        direction               = "EGRESS"
        action                  = "allow"
        rule_name               = "130011"
        disabled                = false
        description             = "Allow Windows KMS Egress through grp-sp-npd-strict (Internet Egress - L7)"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["100.126.0.0/16"]
          dest_fqdns     = ["kms.windows.googlecloud.com"]
          dest_ip_ranges = ["35.190.247.13/32"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "130012" = { # Global Egress - GCP Private API range for internal access #
        priority                = 130012
        direction               = "EGRESS"
        action                  = "allow"
        rule_name               = "130012"
        disabled                = false
        description             = "Allow Egress traffic to GCP Private API range for internal access through grp-sp-npd-strict"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          # TODO: clean up GKE ranges "10.255.101.0/24", "10.255.102.0/24", confirm with Partha
          src_ip_ranges  = ["100.126.0.0/16", "10.255.101.0/24", "10.255.102.0/24", "192.168.128.0/17", "198.18.0.0/17"]
          dest_ip_ranges = ["199.36.153.8/30", "34.126.0.0/18"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "130014" = { # Global Egress - NewRelic traffic #
        priority                = 130014
        direction               = "EGRESS"
        action                  = "allow"
        rule_name               = "130014"
        disabled                = false
        description             = "Allow NewRelic Egress through grp-sp-npd-strict"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges = ["100.126.0.0/16", "10.255.101.0/24", "10.255.102.0/24", "198.18.0.0/17"]
          dest_fqdns    = ["collector.newrelic.com", "aws-api.newrelic.com", "cloud-collector.newrelic.com", "bam.nr-data.net", "bam-cell.nr-data.net", "csec.nr-data.net", "insights-collector.newrelic.com", "log-api.newrelic.com", "metric-api.newrelic.com", "trace-api.newrelic.com", "infra-api.newrelic.com", "identity-api.newrelic.com", "infrastructure-command-api.newrelic.com", "nrql-lookup.service.newrelic.com", "mobile-collector.newrelic.com", "mobile-crash.newrelic.com", "mobile-symbol-upload.newrelic.com", "otlp.nr-data.net", "collector.eu.newrelic.com", "collector.eu01.nr-data.net", "aws-api.eu.newrelic.com", "aws-api.eu01.nr-data.net", "cloud-collector.eu.newrelic.com", "bam.eu01.nr-data.net", "csec.eu01.nr-data.net", "insights-collector.eu01.nr-data.net", "log-api.eu.newrelic.com", "metric-api.eu.newrelic.com", "trace-api.eu.newrelic.com", "infra-api.eu.newrelic.com", "infra-api.eu01.nr-data.net", "identity-api.eu.newrelic.com", "infrastructure-command-api.eu.newrelic.com", "nrql-lookup.service.eu.newrelic.com", "mobile-collector.eu01.nr-data.net", "mobile-crash.eu01.nr-data.net", "mobile-symbol-upload.eu01.nr-data.net", "otlp.eu01.nr-data.net", "download.newrelic.com", "api.newrelic.com"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["443", "4317", "4318"]
            },
          ]
        }
      },
      "130015" = { # Egress for Serverless VPC Connector Range to Loadbalancer Health Check  #
        priority                = 130015
        direction               = "EGRESS"
        action                  = "allow"
        rule_name               = "130015"
        disabled                = false
        description             = "Serverless VPC Connector Range to GCP Loadbalancer Health Check Range"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["192.168.255.224/28"]
          dest_ip_ranges = ["35.199.224.0/19"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["667"]
            },
            {
              ip_protocol = "udp"
              ports       = ["665-666"]
            },
            {
              ip_protocol = "icmp"
              ports       = []
            },
          ]
        }
      },
      "130020" = { # [Exception] - RITM11915511 - Egress for APP2003759 Pelican VMs #
        priority                = 130020
        direction               = "EGRESS"
        action                  = "allow"
        rule_name               = "130020"
        disabled                = false
        description             = "[Exception] - RITM11915511 - Egress for APP2003759 Pelican VMs"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges = [
            "100.126.3.19/32",
            "100.126.3.20/32",
          ]
          dest_ip_ranges = ["0.0.0.0/0"]
          layer4_configs = [
            {
              ip_protocol = "tcp"
              ports       = ["80", "443"]
            },
          ]
        }
      },
      "149997" = { # Catch all Internet Egress for L7 Inspection - Americas  #
        priority                = 149997
        direction               = "EGRESS"
        action                  = "apply_security_profile_group"
        security_profile_group  = "//networksecurity.googleapis.com/organizations/583263843096/locations/global/securityProfileGroups/grp-vfw-am-npd-custom"
        rule_name               = "149997"
        disabled                = false
        description             = "Catch all Internet Egress for L7 Inspection - Americas"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["100.126.0.0/17", "198.18.0.0/17"]
          dest_ip_ranges = ["0.0.0.0/0"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "149998" = { # Catch all Internet Egress for L7 Inspection - Asia Pacific  #
        priority                = 149998
        direction               = "EGRESS"
        action                  = "apply_security_profile_group"
        security_profile_group  = "//networksecurity.googleapis.com/organizations/583263843096/locations/global/securityProfileGroups/grp-vfw-ap-npd-custom"
        rule_name               = "149998"
        disabled                = false
        description             = "Catch all Internet Egress for L7 Inspection - Asia Pacific"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["100.126.192.0/18", "198.18.0.0/17"]
          dest_ip_ranges = ["0.0.0.0/0"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "149999" = { # Catch all Internet Egress for L7 Inspection - Europe  #
        priority                = 149999
        direction               = "EGRESS"
        action                  = "apply_security_profile_group"
        security_profile_group  = "//networksecurity.googleapis.com/organizations/583263843096/locations/global/securityProfileGroups/grp-vfw-eu-npd-custom"
        rule_name               = "149999"
        disabled                = false
        description             = "Catch all Internet Egress for L7 Inspection - Europe"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        tls_inspect             = false
        match = {
          src_ip_ranges  = ["100.126.128.0/18", "198.18.0.0/17"]
          dest_ip_ranges = ["0.0.0.0/0"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "200000" = { # Explicit Internet Egress Block #
        priority                = 200000
        direction               = "EGRESS"
        action                  = "deny"
        rule_name               = "200000"
        disabled                = false
        description             = "Explicit Internet Egress Block"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges  = ["0.0.0.0/0"]
          dest_ip_ranges = ["0.0.0.0/0"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "200001" = { # Explicit Internet Ingress Block #
        priority                = 200001
        direction               = "INGRESS"
        action                  = "deny"
        rule_name               = "200001"
        disabled                = false
        description             = "Explicit Internet Ingress Block"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges  = ["0.0.0.0/0"]
          dest_ip_ranges = ["0.0.0.0/0"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "200002" = { # Explicit IPv6 Internet Egress Block #
        priority                = 200002
        direction               = "EGRESS"
        action                  = "deny"
        rule_name               = "200002"
        disabled                = false
        description             = "Explicit IPv6 Internet Egress Block"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges  = ["::/0"]
          dest_ip_ranges = ["::/0"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
      "200003" = { # Explicit IPv6 Internet Ingress Block #
        priority                = 200003
        direction               = "INGRESS"
        action                  = "deny"
        rule_name               = "200003"
        disabled                = false
        description             = "Explicit IPv6 Internet Ingress Block"
        enable_logging          = true
        target_service_accounts = []
        target_resources        = []
        match = {
          src_ip_ranges  = ["::/0"]
          dest_ip_ranges = ["::/0"]
          layer4_configs = [
            {
              ip_protocol = "all"
              ports       = []
            },
          ]
        }
      },
    }
  }
}

security_profile_groups = {
  "sp-npd-threat-strict" = {
    name        = "sp-npd-threat-strict"
    parent      = "organizations/583263843096"
    description = "Security Profile for Threat Protection"
    type        = "THREAT_PREVENTION"
    threat_prevention_profile = {
      "one" : {
        severity_overrides = {
          "Critical" : {
            action   = "DENY"
            severity = "CRITICAL"
          },
          "High" : {
            action   = "DENY"
            severity = "HIGH"
          },
          "Medium" : {
            action   = "DEFAULT_ACTION"
            severity = "MEDIUM"
          },
          "Low" : {
            action   = "DEFAULT_ACTION"
            severity = "LOW"
          },
          "Informational" : {
            action   = "ALLOW"
            severity = "INFORMATIONAL"
          },
        },
        threat_overrides = {}
      }
    }
    spg_name        = "grp-sp-npd-strict"
    spg_parent      = "organizations/583263843096"
    spg_description = "Strict Security Profile Group for Threat Protection"
  },
  "sp-npd-threat-balanced" = {
    name        = "sp-npd-threat-balanced"
    parent      = "organizations/583263843096"
    description = "Security Profile for Threat Protection"
    type        = "THREAT_PREVENTION"
    threat_prevention_profile = {
      "one" : {
        severity_overrides = {
          "Critical" : {
            action   = "DENY"
            severity = "CRITICAL"
          },
          "High" : {
            action   = "DEFAULT_ACTION"
            severity = "HIGH"
          },
          "Medium" : {
            action   = "DEFAULT_ACTION"
            severity = "MEDIUM"
          },
          "Low" : {
            action   = "DEFAULT_ACTION"
            severity = "LOW"
          },
          "Informational" : {
            action   = "ALLOW"
            severity = "INFORMATIONAL"
          },
        },
        threat_overrides = {}
      }
    }
    spg_name        = "grp-sp-npd-balanced"
    spg_parent      = "organizations/583263843096"
    spg_description = "Balanced Security Profile Group for Threat Protection"
  }
}

security_address_groups = {
  "grp-ext-dc-azurearc-ipv4" = {
    name        = "grp-ext-dc-azurearc-ipv4"
    capacity    = 500
    type        = "IPV4"
    description = "grp-ext-dc-azurearc-ipv4"
    parent      = "organizations/583263843096"
    labels      = {}
    items       = ["4.145.72.0/29", "4.145.72.8/31", "4.150.233.30/31", "4.150.234.24/29", "4.150.242.0/29", "4.150.244.0/23", "4.151.99.20/31", "4.151.99.72/29", "4.171.27.116/31", "4.171.27.176/29", "4.190.132.42/31", "4.190.132.184/29", "4.200.250.192/31", "4.210.131.40/29", "4.210.131.48/31", "4.232.42.0/31", "4.232.42.12/30", "4.232.48.0/29", "4.232.125.178/32", "4.240.144.50/31", "4.240.144.80/29", "4.243.24.48/29", "4.243.24.56/31", "9.160.51.208/30", "9.160.80.56/32", "9.205.43.208/30", "9.205.75.48/32", "13.66.143.219/32", "13.66.149.68/31", "13.67.15.1/32", "13.67.15.124/30", "13.69.239.84/30", "13.69.239.88/32", "13.70.79.64/32", "13.70.79.198/31", "13.71.175.129/32", "13.71.177.224/32", "13.71.199.117/32", "13.73.244.196/32", "13.73.253.124/30", "13.74.107.94/31", "13.77.53.221/32", "13.78.111.193/32", "13.81.244.155/32", "13.86.223.80/32", "13.89.179.20/30", "13.89.179.24/32", "13.90.194.180/32", "20.6.141.126/31", "20.17.28.8/29", "20.17.28.80/31", "20.17.125.68/30", "20.17.131.32/32", "20.17.138.132/31", "20.17.138.168/29", "20.18.7.60/31", "20.18.7.128/29", "20.21.46.136/31", "20.21.69.176/31", "20.21.77.184/31", "20.36.122.52/30", "20.37.66.52/30", "20.37.196.248/30", "20.37.226.52/30", "20.37.228.8/30", "20.38.87.188/30", "20.38.138.56/30", "20.38.141.8/30", "20.38.149.130/32", "20.38.157.132/31", "20.39.12.228/30", "20.39.14.84/30", "20.40.200.152/29", "20.40.224.52/30", "20.41.67.84/30", "20.41.69.52/30", "20.41.195.252/30", "20.41.208.16/30", "20.42.65.86/31", "20.42.74.230/32", "20.42.74.232/30", "20.42.228.216/30", "20.43.43.160/30", "20.43.45.240/30", "20.43.67.88/30", "20.43.121.252/32", "20.43.123.220/30", "20.44.13.240/31", "20.44.19.6/31", "20.44.29.50/31", "20.44.31.36/30", "20.45.127.8/30", "20.45.127.12/32", "20.45.197.224/30", "20.45.199.32/30", "20.45.208.12/30", "20.45.208.40/30", "20.48.192.76/30", "20.49.95.58/31", "20.49.99.12/30", "20.49.102.212/30", "20.49.109.32/30", "20.49.113.12/30", "20.49.114.52/30", "20.49.120.32/30", "20.49.125.188/30", "20.50.1.196/30", "20.50.201.210/31", "20.50.201.212/30", "20.52.72.60/30", "20.53.0.34/31", "20.53.0.112/30", "20.53.0.120/29", "20.53.41.44/30", "20.61.96.184/30", "20.83.192.208/30", "20.83.192.212/32", "20.91.96.162/31", "20.91.100.128/29", "20.91.151.152/29", "20.91.152.84/31", "20.99.27.84/31", "20.99.27.96/29", "20.100.21.120/29", "20.100.21.128/31", "20.111.72.136/29", "20.113.251.38/31", "20.125.173.160/31", "20.125.205.160/31", "20.150.165.140/30", "20.150.190.84/30", "20.151.32.136/30", "20.164.154.166/31", "20.164.158.128/29", "20.167.131.114/31", "20.167.131.120/29", "20.170.175.0/29", "20.175.7.6/31", "20.175.7.128/29", "20.187.194.204/30", "20.189.111.204/30", "20.189.171.108/30", "20.189.173.48/30", "20.191.160.28/30", "20.192.34.68/32", "20.192.101.26/31", "20.192.164.176/30", "20.192.228.252/30", "20.193.96.16/30", "20.193.160.230/32", "20.194.68.148/31", "20.194.129.106/31", "20.203.93.28/31", "20.203.93.80/29", "20.204.199.98/31", "20.204.199.104/29", "20.205.77.198/32", "20.205.77.208/30", "20.205.85.198/31", "20.206.6.188/30", "20.207.175.32/29", "20.207.175.102/31", "20.208.21.162/31", "20.208.151.204/31", "20.208.152.48/29", "20.211.230.248/29", "20.213.229.2/31", "20.213.229.8/29", "20.214.135.216/29", "20.214.135.224/31", "20.215.21.178/32", "20.215.170.104/30", "20.215.174.6/31", "20.215.174.24/29", "20.217.9.46/31", "20.217.10.36/30", "20.217.13.112/29", "20.217.62.136/32", "20.218.190.20/31", "20.218.190.88/29", "20.220.7.200/29", "20.220.7.208/31", "20.226.211.158/31", "20.226.212.160/29", "20.241.119.28/31", "20.241.119.104/29", "20.244.194.6/31", "20.244.194.8/29", "20.252.212.216/29", "20.252.212.224/31", "23.97.88.88/29", "23.98.86.58/31", "23.98.104.12/30", "23.98.108.32/30", "23.100.218.124/31", "23.100.218.152/29", "40.64.132.84/30", "40.64.135.72/30", "40.67.122.108/30", "40.67.122.112/32", "40.67.122.120/29", "40.69.111.34/31", "40.69.111.192/30", "40.69.116.96/29", "40.70.151.194/32", "40.70.151.196/30", "40.71.15.194/32", "40.74.102.16/30", "40.74.150.116/30", "40.74.150.120/32", "40.78.204.46/32", "40.78.239.96/31", "40.78.253.84/31", "40.79.138.46/31", "40.79.146.46/32", "40.79.150.112/30", "40.79.167.16/30", "40.79.167.20/32", "40.79.173.36/32", "40.79.191.216/32", "40.80.53.2/31", "40.80.59.24/30", "40.80.103.250/31", "40.80.172.12/30", "40.89.20.128/30", "40.89.23.32/30", "40.89.121.188/31", "40.115.144.0/30", "40.117.28.40/29", "40.117.28.96/31", "40.119.9.232/30", "40.120.8.184/30", "40.120.75.58/32", "40.120.77.176/30", "40.124.65.160/31", "48.216.8.52/32", "48.216.28.144/30", "48.219.203.208/30", "48.219.232.56/32", "51.4.131.208/30", "51.4.160.56/32", "51.11.98.64/29", "51.11.192.34/31", "51.12.22.220/30", "51.12.75.188/30", "51.12.168.72/30", "51.12.229.232/30", "51.13.128.80/30", "51.53.41.76/30", "51.53.43.104/29", "51.53.43.112/31", "51.53.110.138/32", "51.53.136.60/31", "51.53.139.72/29", "51.53.182.200/30", "51.53.191.138/32", "51.103.205.160/31", "51.104.15.254/32", "51.104.28.216/30", "51.104.31.172/30", "51.105.71.144/31", "51.105.77.50/31", "51.105.90.148/30", "51.107.50.56/30", "51.107.53.32/30", "51.107.60.152/32", "51.107.129.104/30", "51.107.146.52/30", "51.107.193.4/30", "51.116.49.136/30", "51.116.145.136/30", "51.116.146.212/30", "51.116.158.60/31", "51.116.243.218/31", "51.116.251.186/32", "51.116.253.164/30", "51.120.42.56/30", "51.120.44.196/30", "51.120.100.156/31", "51.120.109.26/31", "51.120.183.220/31", "51.120.183.248/29", "51.120.213.26/32", "51.120.214.148/30", "51.120.226.52/30", "51.137.164.76/30", "51.137.166.40/30", "51.138.160.92/30", "51.140.151.168/30", "51.140.212.216/31", "51.140.215.180/30", "52.136.51.68/30", "52.138.90.54/31", "52.138.229.96/31", "52.140.107.92/30", "52.140.110.108/30", "52.146.79.132/30", "52.146.130.180/30", "52.150.152.204/30", "52.150.156.36/30", "52.162.111.132/32", "52.167.111.168/31", "52.168.118.130/32", "52.172.85.50/31", "52.172.86.48/29", "52.178.17.240/31", "52.182.141.60/31", "52.228.84.80/30", "52.231.23.10/32", "52.231.151.80/30", "52.233.105.184/29", "52.233.111.64/31", "52.236.189.74/32", "52.240.244.228/30", "52.246.157.2/31", "57.151.220.212/30", "65.52.252.250/31", "68.154.136.52/32", "68.210.152.56/32", "68.210.172.144/30", "68.211.13.16/30", "68.211.152.56/32", "68.219.196.6/31", "68.219.197.8/29", "68.221.41.72/30", "68.221.44.32/29", "68.221.44.40/31", "68.221.98.112/32", "70.153.165.84/30", "70.153.176.52/32", "74.242.3.192/29", "74.242.3.200/31", "74.249.120.4/31", "74.249.127.128/29", "74.249.138.70/31", "74.249.138.88/29", "98.66.128.36/31", "98.66.128.72/29", "102.37.64.160/30", "102.133.57.188/30", "102.133.127.176/31", "102.133.154.6/31", "102.133.218.52/30", "102.133.219.188/30", "102.133.254.200/30", "102.133.254.204/32", "104.46.162.2/32", "104.46.162.28/30", "104.46.163.96/29", "104.46.178.0/30", "104.211.146.248/30", "104.214.164.48/31", "108.140.1.96/29", "108.140.1.104/31", "137.135.98.137/32", "158.23.10.112/32", "158.23.96.20/30", "158.23.115.20/31", "158.23.115.48/29", "168.61.233.50/31", "168.61.233.56/29", "172.167.234.102/31", "172.167.236.56/29", "172.172.252.64/29", "172.172.252.72/31", "172.182.155.194/31", "172.182.155.200/29", "172.187.0.16/29", "172.187.0.24/31", "172.202.64.0/22", "172.204.165.72/30", "172.204.177.160/32", "172.215.202.52/32", "191.233.207.26/32", "191.233.207.30/31", "191.234.136.44/30", "191.234.138.144/30", "191.234.149.138/32", "191.234.157.42/32", "191.234.157.172/30", "191.237.224.230/32", "20.209.230.225/32", "20.209.230.161/32", "52.239.213.4/32", "104.85.2.183/32", "23.219.50.151/32", "23.221.245.214/32"]
  },
  "grp-ext-dc-azurearc-ipv6" = {
    name        = "grp-ext-dc-azurearc-ipv6"
    capacity    = 100
    type        = "IPV6"
    description = "grp-ext-dc-azurearc-ipv6"
    parent      = "organizations/583263843096"
    labels      = {}
    items       = ["2603:1010:304:5::420/124", "2603:1010:404:5::4d0/124", "2603:1010:502:2::130/124", "2603:1020:104:6::80/124", "2603:1020:605:6::180/124", "2603:1020:905:5::440/124", "2603:1020:b04:5::5b0/124", "2603:1020:d04:5::4c0/124", "2603:1020:f04:6::4c0/124", "2603:1020:1204:2::670/124", "2603:1020:1403:2::570/124", "2603:1020:1502:2::20/124", "2603:1020:1602:2::20/124", "2603:1030:13:200::/62", "2603:1030:702:2::570/124", "2603:1030:902:2::280/124", "2603:1030:a09:100::/63", "2603:1030:1102:2::200/124", "2603:1030:1202:2::20/124", "2603:1040:806:3::7c0/124", "2603:1040:c06:6::210/124", "2603:1040:e05:6::90/124", "2603:1040:1002:5::420/124", "2603:1040:1202:2::680/124", "2603:1040:1302:2::620/124", "2603:1040:1402:3::2b0/124", "2603:1040:1602:2::130/124", "2603:1040:1702:2::20/124", "2603:1040:1802:1::710/124", "2603:1050:301:2::200/124"]
  },
  "grp-ext-dc-offsite-vault-datacenters" = {
    name        = "grp-ext-dc-offsite-vault-datacenters"
    capacity    = 100
    type        = "IPV4"
    description = "grp-ext-dc-offsite-vault-datacenters"
    parent      = "organizations/583263843096"
    labels      = {}
    items       = ["83.126.33.0/24", "83.126.49.0/24", "148.51.147.0/24", "148.51.148.0/24", "148.51.149.0/24", "148.51.150.0/24", "148.51.151.0/24", "148.51.152.0/24", "148.51.153.0/24", "172.97.15.128/26", "199.47.127.64/26", "205.235.80.128/25", "205.235.90.0/24", "208.66.137.0/24", "208.66.140.64/26", "208.66.141.0/25", "216.229.148.0/24", "216.229.151.192/26", "216.229.155.0/24"]
  },
  "grp-mcd-onprem-prefixes" = {
    name        = "grp-mcd-onprem-prefixes"
    capacity    = 100
    type        = "IPV4"
    description = "grp-mcd-onprem-prefixes"
    parent      = "organizations/583263843096"
    labels      = {}
    items       = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "103.13.147.0/24", "142.11.128.0/18", "152.140.0.0/15", "152.142.0.0/16", "152.144.73.0/24", "66.111.130.0/24", "66.111.154.0/23", "66.111.156.0/22", "66.111.183.128/25", "69.168.17.0/24"]
  },
  "grp-mcd-gcp-npd-domaincontrollers" = {
    name        = "grp-mcd-gcp-npd-domaincontrollers"
    capacity    = 20
    type        = "IPV4"
    description = "grp-mcd-onprem-prefixes"
    parent      = "organizations/583263843096"
    labels      = {}
    items       = ["100.126.193.26", "100.126.193.10", "100.126.129.10", "100.126.129.26", "100.126.1.10", "100.126.1.26"]
  },
  "grp-mcd-gcp-npd-egress-common" = {
    name        = "grp-mcd-gcp-npd-egress-common"
    capacity    = 50
    type        = "IPV4"
    description = "grp-mcd-gcp-npd-egress-common"
    parent      = "organizations/583263843096"
    labels      = {}
    items       = ["100.126.2.2", "198.18.0.10"]
  },
  "grp-mcd-gcp-npd-egress-all" = {
    name        = "grp-mcd-gcp-npd-egress-all"
    capacity    = 50
    type        = "IPV4"
    description = "grp-mcd-gcp-npd-egress-all"
    parent      = "organizations/583263843096"
    labels      = {}
    items       = ["100.126.193.26", "100.126.193.10", "100.126.129.10", "100.126.129.26", "100.126.1.10", "100.126.1.26"]
  },
  "grp-mcd-gcp-npd-all-ranges" = {
    name        = "grp-mcd-gcp-npd-all-ranges"
    capacity    = 10
    type        = "IPV4"
    description = "grp-mcd-gcp-npd-all-ranges"
    parent      = "organizations/583263843096"
    labels      = {}
    items       = ["100.126.0.0/16", "10.255.101.0/24", "10.255.102.0/24", "198.18.0.0/17"]
  },
  "grp-3pfw-npd" = {
    name        = "grp-3pfw-npd"
    capacity    = 10
    type        = "IPV4"
    description = "grp-3pfw-npd"
    parent      = "organizations/583263843096"
    labels      = {}
    items = [
      "100.126.193.64/27",
      "100.126.193.32/27",
      "100.126.129.32/27",
      "100.126.129.64/27",
      "100.126.1.96/27",
      "100.126.1.128/27",
      "100.126.2.2/32"
    ]
  },
}

ngfw_consumer = {
  am = {
    parent                      = "organizations/583263843096"
    intercept_group             = "projects/prj-cp-3pfw-npd01/locations/global/interceptEndpointGroups/vfw-am-epg"
    security_profile_name       = "sp-vfw-am-npd-custom"
    security_profile_group_name = "grp-vfw-am-npd-custom"
  },
  ap = {
    parent                      = "organizations/583263843096"
    intercept_group             = "projects/prj-cp-3pfw-npd01/locations/global/interceptEndpointGroups/vfw-ap-epg"
    security_profile_name       = "sp-vfw-ap-npd-custom"
    security_profile_group_name = "grp-vfw-ap-npd-custom"
  },
  eu = {
    parent                      = "organizations/583263843096"
    intercept_group             = "projects/prj-cp-3pfw-npd01/locations/global/interceptEndpointGroups/vfw-eu-epg"
    security_profile_name       = "sp-vfw-eu-npd-custom"
    security_profile_group_name = "grp-vfw-eu-npd-custom"
  },
}