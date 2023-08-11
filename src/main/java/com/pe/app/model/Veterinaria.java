package com.pe.app.model;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name="verterinarias")
public class Veterinaria {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String nombre;
	private String direccion;
	private String telefono;
	
	@OneToMany(mappedBy="veterinaria",cascade = CascadeType.MERGE)
	@JsonIgnore
	private Set<DuenoVeterinaria> duenoVet=new HashSet<>();
	
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getNombre() {
		return nombre;
	}
	public void setNombre(String nombre) {
		this.nombre = nombre;
	}
	public String getDireccion() {
		return direccion;
	}
	public void setDireccion(String direccion) {
		this.direccion = direccion;
	}
	public String getTelefono() {
		return telefono;
	}
	public void setTelefono(String telefono) {
		this.telefono = telefono;
	}
	public Set<DuenoVeterinaria> getDuenoVet() {
		return duenoVet;
	}
	public void setDuenoVet(Set<DuenoVeterinaria> duenoVet) {
		this.duenoVet = duenoVet;
	}
	
	
	
}
