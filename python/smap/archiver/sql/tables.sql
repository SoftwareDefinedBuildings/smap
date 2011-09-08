
DROP TABLE IF EXISTS metadata;
DROP TABLE IF EXISTS stream;
DROP TABLE IF EXISTS subscription;

-- table for list of sMAP sources we should be subscribed to
CREATE TABLE subscription (
       `id` INT AUTO_INCREMENT PRIMARY KEY,
       `uuid` VARCHAR(36),
       `url` VARCHAR(512) NOT NULL,
       `resource` VARCHAR(512) NOT NULL DEFAULT '/+',
       `key` VARCHAR(36),
       INDEX uuid_ind(uuid)
) ENGINE=InnoDB;

-- list of streams associated with a sMAP source
CREATE TABLE stream (
       `id` INT AUTO_INCREMENT PRIMARY KEY,
       `subscription_id` INT NOT NULL,
       `uuid` VARCHAR(36) UNIQUE,

       INDEX uuid_ind(uuid),
       INDEX subscription_ind(subscription_id),
       FOREIGN KEY (subscription_id) REFERENCES subscription(id)
         ON DELETE CASCADE
) ENGINE=InnoDB;

-- table for sMAP stream metadata
CREATE TABLE metadata2 (
       `id` INT AUTO_INCREMENT PRIMARY KEY,
       `stream_id` INT,

       `tagname` VARCHAR(64) NOT NULL,
       `tagval` TEXT NOT NULL,

       INDEX stream_id_ind(stream_id),
       UNIQUE INDEX uuid_anchor_ind(stream_id, tagname),
       FOREIGN KEY (stream_id) REFERENCES stream(id)
         ON DELETE CASCADE
) ENGINE=InnoDB;
