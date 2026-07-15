terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.0.0"
    }
    zitadel = {
      source  = "zitadel/zitadel"
      version = ">= 1.2.0"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.0.0"
    }
  }
}

variable "vault_addr" {
  default = "http://vault:8200"
}

variable "zitadel_domain" {
  default = "zitadel"
}

variable "zitadel_port" {
  default = "8080"
}

provider "vault" {
  address = var.vault_addr
  token   = "root"
}

# The admin PAT is bootstrapped by ZITADEL itself on first boot (see
# ZITADEL_FIRSTINSTANCE_PATPATH in docker-compose.yml) and written to a
# volume this container also mounts -- lets Terraform authenticate without
# a manual setup wizard click-through, same pattern as Authentik's
# bootstrap token before it.
provider "zitadel" {
  domain       = var.zitadel_domain
  port         = var.zitadel_port
  insecure     = true
  access_token = trimspace(file("/zitadel-bootstrap/admin.pat"))
}
