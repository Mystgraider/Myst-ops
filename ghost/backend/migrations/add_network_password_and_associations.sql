-- Add password field and support for multiple person/business associations
-- Created: 2026-01-28

-- Add password field to wireless_networks
ALTER TABLE wireless_networks
ADD COLUMN IF NOT EXISTS password VARCHAR(255);

-- Add array fields for multiple associations
ALTER TABLE wireless_networks
ADD COLUMN IF NOT EXISTS associated_person_ids INTEGER[],
ADD COLUMN IF NOT EXISTS associated_business_ids INTEGER[];

-- Add comment for documentation
COMMENT ON COLUMN wireless_networks.password IS 'Network password if known (stored for investigative purposes)';
COMMENT ON COLUMN wireless_networks.associated_person_ids IS 'Array of person IDs associated with this network';
COMMENT ON COLUMN wireless_networks.associated_business_ids IS 'Array of business IDs associated with this network';
