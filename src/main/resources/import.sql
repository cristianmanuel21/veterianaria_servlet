insert into animales(nombre) values('perro');
insert into animales(nombre) values('gato');
insert into animales(nombre) values('loro');

insert into chips(marca,descripcion) values('LG','chip de la marca koreana');
insert into chips(marca,descripcion) values('SONY','chip de la marca japonesa');
insert into chips(marca,descripcion) values('HUAWEY','chip de la marca china');

insert into duenos(nombre,apellido_paterno,apellido_materno,telefono,celular,direccion,correo) values ('Paul','Perez','Diaz','3323326','919058116','Los heraldos negros 123','cristianmanuel.9385@gmail.com');
insert into duenos(nombre,apellido_paterno,apellido_materno,telefono,celular,direccion,correo) values ('Luciano','Perez','Del Solar','3323325','919058111','Los heraldos blancos 321','milagros.100123@gmail.com');
insert into duenos(nombre,apellido_paterno,apellido_materno,telefono,celular,direccion,correo) values ('Pedro','Castillo','Terrones','3323322','919058112','Los quesos amarillo 258','casnillo@gmail.com');

insert into mascotas(nombre,edad,chip_id,animal_id,dueno_id) values('Peluche',13,1,1,1);
insert into mascotas(nombre,edad,chip_id,animal_id,dueno_id) values('Minino',5,2,2,2);
insert into mascotas(nombre,edad,chip_id,animal_id,dueno_id) values('Condorito',27,3,3,3);

insert into verterinarias(nombre,direccion,telefono) values('Las mascotas','Av Riva Aguero 1423','3335481');
insert into verterinarias(nombre,direccion,telefono) values('Las patitas locas','Av La Mar 5954','3335480');

insert into duenoveterinarias(dueno_id,veterinaria_id,created_at) values(1,1,'2023-02-15');
insert into duenoveterinarias(dueno_id,veterinaria_id,created_at) values(2,1,'2023-05-19');
insert into duenoveterinarias(dueno_id,veterinaria_id,created_at) values(3,2,'2023-06-21');

insert into roles(id,name) values (1,'ROLE_USER');
insert into roles(id,name) values (2,'ROLE_MODERATOR');
insert into roles(id,name) values (3,'ROLE_ADMIN');