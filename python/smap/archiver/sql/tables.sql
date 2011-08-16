
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
CREATE TABLE metadata (
       `id` INT AUTO_INCREMENT PRIMARY KEY,
       `stream_id` INT,
       `anchor` BIGINT NOT NULL,
       `duration` BIGINT,

       `tagname` VARCHAR(64) NOT NULL,
       `tagval` TEXT NOT NULL,

       INDEX stream_id_ind(stream_id),
       INDEX uuid_anchor_ind(stream_id, anchor),
       FOREIGN KEY (stream_id) REFERENCES stream(id)
         ON DELETE CASCADE
) ENGINE=InnoDB;

-- insert into subscription values (1, UUID(), 'http://localhost:8080/', '/+', '2ZH78oL1aP3QfVnrkDu7VoYnDarbuunVMzGA');
-- insert into stream values (1, 1, 'f421c274-c3c1-11e0-851c-0026bb56ec92');
