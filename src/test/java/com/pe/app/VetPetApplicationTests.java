package com.pe.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import java.time.LocalDate;
import java.util.List;
import java.util.Set;
import com.pe.app.model.*;
import com.pe.app.repository.*;
import com.pe.app.security.payload.request.LoginRequest;
import com.pe.app.security.payload.request.SignupRequest;
import com.pe.app.security.payload.response.JwtResponse;
import com.pe.app.security.payload.response.MessageResponse;
import com.pe.app.services.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VetPetApplicationTests {
	
	@Autowired
	private MascotaService mascotaService;
	
	@Autowired
	private ChipService chipService;
	
	@Autowired
	private DuenoService duenoService;
	
	@Autowired
	private AnimalService animalService;
	
	@Autowired
	private VeterinariaService veterinariaService;

	@Autowired
	RoleRepository roleRepository;

	static String token=" ";
	
	
	@Autowired
	private WebTestClient client;

	@Test
	@Order(1)
	void saveRole() {
		Role role_user=new Role(ERole.ROLE_USER);
		Role role_admin=new Role(ERole.ROLE_ADMIN);
		Role role_mod=new Role(ERole.ROLE_MODERATOR);
		List<Role> roles=List.of(role_mod,role_admin,role_user);
		roleRepository.saveAll(roles);
	}

	@Test
	@Order(2)
	void saveUser(){
		SignupRequest s=new SignupRequest();
		s.setEmail("cristianmanuel.25@gmail.com");
		s.setUsername("cristian777");
		s.setPassword("peru1234");
		s.setRole(Set.of("admin"));
		//when
		client.post().uri("/api/auth/signup")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(s)
				.exchange()
				//then
				.expectStatus().isOk()
				.expectHeader().contentType(MediaType.APPLICATION_JSON)
				.expectBody(MessageResponse.class)
				.consumeWith(response->{
					MessageResponse si=response.getResponseBody();
					assertNotNull(si);
					assertEquals(si.getMessage(),"User registered successfully!");
				});
	}

	@Test
	@Order(3)
	void createToken(){
		LoginRequest l=new LoginRequest();
		l.setUsername("cristian777");
		l.setPassword("peru1234");
		//when
		client.post().uri("/api/auth/signin")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(l)
				.exchange()
				//then
				.expectStatus().isOk()
				.expectHeader().contentType(MediaType.APPLICATION_JSON)
				.expectBody(JwtResponse.class)
				.consumeWith(response->{
					JwtResponse jwt=response.getResponseBody();
					assertNotNull(jwt);
					assertEquals(jwt.getUsername(),"cristian777");
					token=jwt.getAccessToken();

				});
		//System.out.println("El JWT es "+token);

	}


	@Test
	@Order(4)
	void saveChip() {
		//given
				Chip chip=new Chip();
				chip.setMarca("SONY");
				chip.setDescripcion("Chip sony experimental");
				//when
				client.post().uri("/chip")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(chip)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.exchange()
				//then
				.expectStatus().isCreated()
				.expectHeader().contentType(MediaType.APPLICATION_JSON)
				.expectBody(Chip.class)
				.consumeWith(response->{
					Chip aut=response.getResponseBody();
					assertNotNull(aut);
					assertEquals(aut.getMarca(), "SONY");
				});
	}

	@Test
	@Order(5)
	void UpdateChip() {
		//given
		Chip chip=chipService.getById(1L);
		chip.setDescripcion("Chip Sony experimental 2");

		//when
		client.put().uri("/chip/{id}",chip.getId())
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(chip)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.exchange()
				//then
				.expectStatus().isCreated()
				.expectHeader().contentType(MediaType.APPLICATION_JSON)
				.expectBody(Chip.class)
				.consumeWith(response->{
					Chip aut=response.getResponseBody();
					assertNotNull(aut);
					assertEquals(aut.getDescripcion(), "Chip Sony experimental 2");
				});
	}
	
	
	@Test
	@Order(6)
	void saveAnimal() {
		//given
				Animal animal=new Animal();
				animal.setNombre("perro");
				
				//when
				client.post().uri("/animal")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(animal)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.exchange()
				//then
				.expectStatus().isCreated()
				.expectHeader().contentType(MediaType.APPLICATION_JSON)
				.expectBody(Animal.class)
				.consumeWith(response->{
					Animal aut=response.getResponseBody();
					assertNotNull(aut);
					assertEquals(aut.getNombre(), "perro");
				});
	}
	
	
	@Test
	@Order(7)
	void saveDueno() {
		//given
				Dueno dueno=new Dueno();
				dueno.setNombre("Cristian Manuel");
				dueno.setApellido_paterno("Diaz");
				dueno.setApellido_materno("Morales");
				dueno.setCelular("919055112");
				dueno.setCorreo("cristian@gmail.com");
				dueno.setDireccion("Los ovnis 123");
				dueno.setTelefono("3323362");
				
				//when
				client.post().uri("/dueno")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(dueno)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.exchange()
				//then
				.expectStatus().isCreated()
				.expectHeader().contentType(MediaType.APPLICATION_JSON)
				.expectBody(Dueno.class)
				.consumeWith(response->{
					Dueno aut=response.getResponseBody();
					assertNotNull(aut);
					assertEquals(aut.getNombre(), "Cristian Manuel");
				});
	}
	
	@Test
	@Order(8)
	void saveDueno2() {
		//given
				Dueno dueno=new Dueno();
				dueno.setNombre("Paul Alfonso");
				dueno.setApellido_paterno("Quispe");
				dueno.setApellido_materno("Mamani");
				dueno.setCelular("919055115");
				dueno.setCorreo("paulino@gmail.com");
				dueno.setDireccion("Los ovnis 1431");
				dueno.setTelefono("3323360");
				
				//when
				client.post().uri("/dueno")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(dueno)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.exchange()
				//then
				.expectStatus().isCreated()
				.expectHeader().contentType(MediaType.APPLICATION_JSON)
				.expectBody(Dueno.class)
				.consumeWith(response->{
					Dueno aut=response.getResponseBody();
					assertNotNull(aut);
					assertEquals(aut.getNombre(), "Paul Alfonso");
				});
	}
	
	@Test
	@Order(9)
	void saveMascota() {
		//given
		Chip chip=chipService.getById(1L);
		Animal animal=animalService.getById(1L);
		Dueno dueno=duenoService.getById(1L);
		Mascota mascota=new Mascota();
		mascota.setNombre("Peluchin");
		mascota.setEdad(11);
		mascota.setAnimal(animal);
		mascota.setChip(chip);
		mascota.setDueno(dueno);
		
		//when
		client.post().uri("/mascota/animal/{animalId}/chip/{chipId}/dueno/{duenoId}",animal.getId(),chip.getId(),dueno.getId())
		.contentType(MediaType.APPLICATION_JSON)
		.bodyValue(mascota)
		.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
		.exchange()
		//then
		.expectStatus().isCreated()
		.expectHeader().contentType(MediaType.APPLICATION_JSON)
		.expectBody(Mascota.class)
		.consumeWith(response->{
			Mascota mascotaF=response.getResponseBody();
			assertNotNull(mascotaF);
			assertEquals(mascotaF.getNombre(), "Peluchin");
			assertEquals(mascotaF.getEdad(), 11);
		});
	}
	
	
	@Test
	@Order(10)
	void saveVeterinario() {
		//given
			    Veterinaria vet=new Veterinaria();
			    vet.setDireccion("Los alamos 531 - Los Olivos");
			    vet.setNombre("Los amantes caninos");
			    vet.setTelefono("3353367");
				//when
				client.post().uri("/veterinaria")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(vet)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.exchange()
				//then
				.expectStatus().isCreated()
				.expectHeader().contentType(MediaType.APPLICATION_JSON)
				.expectBody(Veterinaria.class)
				.consumeWith(response->{
					Veterinaria vetF=response.getResponseBody();
					assertNotNull(vetF);
					assertEquals(vetF.getNombre(), "Los amantes caninos");
					assertEquals(vetF.getDireccion(), "Los alamos 531 - Los Olivos");
				});
	}
	
	
	
	@Test
	@Order(11)
	void saveFavourites() {
		//given
		Veterinaria vet=veterinariaService.getById(1L);
		Dueno dueno=duenoService.getById(1L);
		DuenoVeterinaria duenoVet=new DuenoVeterinaria();
		duenoVet.setCreated_at(LocalDate.now());
		duenoVet.setDueno(dueno);
		duenoVet.setVeterinaria(vet);
		
		//when
		client.post().uri("/duenoveterinaria/dueno/{duenoId}/veterinaria/{veterinariaId}",dueno.getId(), vet.getId())
		.contentType(MediaType.APPLICATION_JSON)
		.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
		.bodyValue(duenoVet)
		.exchange()
		//then
		.expectStatus().isCreated()
		.expectHeader().contentType(MediaType.APPLICATION_JSON)
		.expectBody(DuenoVeterinaria.class)
		.consumeWith(response->{
			DuenoVeterinaria duenoVeterinariaF=response.getResponseBody();
			assertNotNull(duenoVeterinariaF);
			assertEquals(duenoVeterinariaF.getDueno().getNombre(),"Cristian Manuel");
			assertEquals(duenoVeterinariaF.getVeterinaria().getNombre(),"Los amantes caninos");
		});
	}
	
	
	@Test
	@Order(12)
	void saveFavourites2() {
		//given
		Veterinaria vet=veterinariaService.getById(1L);
		Dueno dueno=duenoService.getById(2L);
		DuenoVeterinaria duenoVet=new DuenoVeterinaria();
		duenoVet.setCreated_at(LocalDate.now());
		duenoVet.setDueno(dueno);
		duenoVet.setVeterinaria(vet);
		
		//when
		client.post().uri("/duenoveterinaria/dueno/{duenoId}/veterinaria/{veterinariaId}",dueno.getId(), vet.getId())
		.contentType(MediaType.APPLICATION_JSON)
		.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
		.bodyValue(duenoVet)
		.exchange()
		//then
		.expectStatus().isCreated()
		.expectHeader().contentType(MediaType.APPLICATION_JSON)
		.expectBody(DuenoVeterinaria.class)
		.consumeWith(response->{
			DuenoVeterinaria duenoVeterinariaF=response.getResponseBody();
			assertNotNull(duenoVeterinariaF);
			assertEquals(duenoVeterinariaF.getDueno().getNombre(),"Paul Alfonso");
			assertEquals(duenoVeterinariaF.getVeterinaria().getNombre(),"Los amantes caninos");
		});
	}
	
	
	@Test
	@Order(13)
	void enviarCorreo() {
		//given
		Veterinaria vet=veterinariaService.getById(1L);
		
		//when
		client.get().uri("/duenoveterinaria/email/veterinaria/{id}", vet.getId())
		.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
		.exchange()
		.expectStatus().isOk()
		.expectHeader().contentType(MediaType.APPLICATION_JSON)
		.expectBodyList(Dueno.class)
		.hasSize(2)
        .consumeWith(response->{
			List<Dueno> duenoFinal=response.getResponseBody();
			assertNotNull(duenoFinal);
			assertEquals(duenoFinal.size(),2);
			assertEquals(duenoFinal.get(0).getCorreo(),"cristian@gmail.com");
			assertEquals(duenoFinal.get(1).getCorreo(),"paulino@gmail.com");
			//assertEquals(duenoVeterinariaF.getVeterinaria().getNombre(),"Los amantes caninos");
		});
	}
	
	
	
	

}
