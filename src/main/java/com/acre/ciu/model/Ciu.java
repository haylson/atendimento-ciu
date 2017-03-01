package com.acre.ciu.model;

import java.util.Calendar;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.hibernate.validator.constraints.NotBlank;
import org.hibernate.validator.constraints.br.CPF;
import org.springframework.format.annotation.DateTimeFormat;

@Entity
public class Ciu {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long codigo;
	
	@NotBlank
	@Size(min = 9, max = 15)
	private String numeroBeneficio;
	
	@NotBlank
	@Size(min = 3, max = 60)
	private String nome;
	
	@NotBlank
	@Size(min = 3, max = 60)
	private String endereco;
	
	@NotBlank
	@Size(min = 3, max = 60)
	private String bairro;
	
	@NotBlank
	@CPF
	private String cpf;
	
	private String telefone;
	
	@Size(max = 20)
	private String cid;
	
	@Enumerated
	@NotNull
	private Situacao situacao; 
	
	@DateTimeFormat(pattern="dd/MM/yyyy")
	private Calendar dataAnalise;
	
	@DateTimeFormat(pattern="dd/MM/yyyy")
	private Calendar dataCadastro = Calendar.getInstance();
	
	@Enumerated
	@NotNull
	private Sexo sexo;
	
	@Enumerated
	@NotNull
	private FaixaEtaria faixaEtaria;
	
	@Enumerated
	@NotNull
	private Cor cor;
	
	@Enumerated
	@NotNull
	private EspecificidadeSocial especificidadeSocial;
	
	@Enumerated
	@NotNull
	private EstadoCivil estadoCivil;
	
	@Enumerated
	@NotNull
	private Escolaridade escolaridade;
	
	@Enumerated
	@NotNull
	private VinculoEmpregaticio vinculoEmpregaticio;
	
	@Enumerated
	@NotNull
	private InsercaoMercadoTrabalho insercaoMT;
	
	@Enumerated
	@NotNull
	private RendaFamiliar rendaFamiliar;
	
	@Enumerated
	@NotNull
	private CuidadosConstantes cuidadosConstantes;

	@ManyToOne(fetch=FetchType.EAGER)
	private Usuario usuario;
	
	private boolean deficienciaVisual;
	
	private boolean deficienciaAuditiva;
	
	private boolean deficienciaIntelectual;
	
	private boolean deficienciaTranstornoMental;
	
	private boolean deficienciaDoencaCronica;
	
	private boolean defNeuroMusculoEsqueletica;
	
	private boolean deficienciaMultipla;
	
	private boolean deficienciaNaoInformada;
	
	@Enumerated
	@NotNull
	private RedeEnsino redeEnsino;
	
	@Enumerated
	@NotNull
	private LocalRedeEnsino localRedeEnsino;
	
	@Enumerated
	@NotNull
	private AtendimentoSus atendimentoSus;
	
	@Enumerated
	@NotNull
	private LocalSus localSus;
	
	@Enumerated
	@NotNull
	private UsoMedicamento usoMedicamento;
	
	private boolean medicamentoComprado;
	
	private boolean medicamentoGratuito;
	
	@Enumerated
	@NotNull
	private AcessoLazer acessoLazer;
	
	@Size(min = 3, max = 20)
	private String lazer;
	
	private boolean cras;
	
	private boolean creas;
	
	private boolean servicoConvivencia;
	
	private boolean beneficiosTransferenciaRenda;
	
	private boolean cadunico;
	
	private boolean beneficiosEventuais;
	
	private boolean centroPop;
	
	private boolean albergue;
	
	private boolean semAcessoPoliticaSocial;
	
	@Enumerated
	@NotNull
	private AcessoTransportePublico acessoTransportePublico;
	
	@Enumerated
	@NotNull
	private TransporteAdaptado transporteAdaptado;
	
	@Enumerated
	@NotNull
	private TransporteGratuito transporteGratuito;
	
	private boolean internet;
	
	private boolean computador;
	
	private boolean televisao;
	
	private boolean celular;
	
	private boolean radio;
	
	private boolean semAcesso;
	
	@Enumerated
	@NotNull
	private ConhecimentoBPC conhecimentoBPC;
	
	@Enumerated
	@NotNull
	private EscolhaAPS escolhaAPS;
	
	@Column(columnDefinition="TEXT")
	private String avaliacao;
	
	@Column(columnDefinition="TEXT")
	private String parecer;

	public Long getCodigo() {
		return codigo;
	}

	public void setCodigo(Long codigo) {
		this.codigo = codigo;
	}

	public String getNumeroBeneficio() {
		return numeroBeneficio;
	}

	public void setNumeroBeneficio(String numeroBeneficio) {
		this.numeroBeneficio = numeroBeneficio;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getEndereco() {
		return endereco;
	}

	public void setEndereco(String endereco) {
		this.endereco = endereco;
	}

	public String getBairro() {
		return bairro;
	}

	public void setBairro(String bairro) {
		this.bairro = bairro;
	}

	public String getCpf() {
		return cpf;
	}

	public void setCpf(String cpf) {
		this.cpf = cpf;
	}

	public String getCid() {
		return cid;
	}

	public void setCid(String cid) {
		this.cid = cid;
	}

	public Situacao getSituacao() {
		return situacao;
	}

	public void setSituacao(Situacao situacao) {
		this.situacao = situacao;
	}

	public Calendar getDataAnalise() {
		return dataAnalise;
	}

	public void setDataAnalise(Calendar dataAnalise) {
		this.dataAnalise = dataAnalise;
	}

	public Calendar getDataCadastro() {
		return dataCadastro;
	}

	public void setDataCadastro(Calendar dataCadastro) {
		this.dataCadastro = dataCadastro;
	}

	public Sexo getSexo() {
		return sexo;
	}

	public void setSexo(Sexo sexo) {
		this.sexo = sexo;
	}

	public FaixaEtaria getFaixaEtaria() {
		return faixaEtaria;
	}

	public void setFaixaEtaria(FaixaEtaria faixaEtaria) {
		this.faixaEtaria = faixaEtaria;
	}

	public Cor getCor() {
		return cor;
	}

	public void setCor(Cor cor) {
		this.cor = cor;
	}

	public EspecificidadeSocial getEspecificidadeSocial() {
		return especificidadeSocial;
	}

	public void setEspecificidadeSocial(EspecificidadeSocial especificidadeSocial) {
		this.especificidadeSocial = especificidadeSocial;
	}

	public EstadoCivil getEstadoCivil() {
		return estadoCivil;
	}

	public void setEstadoCivil(EstadoCivil estadoCivil) {
		this.estadoCivil = estadoCivil;
	}

	public Escolaridade getEscolaridade() {
		return escolaridade;
	}

	public void setEscolaridade(Escolaridade escolaridade) {
		this.escolaridade = escolaridade;
	}

	public VinculoEmpregaticio getVinculoEmpregaticio() {
		return vinculoEmpregaticio;
	}

	public void setVinculoEmpregaticio(VinculoEmpregaticio vinculoEmpregaticio) {
		this.vinculoEmpregaticio = vinculoEmpregaticio;
	}

	public InsercaoMercadoTrabalho getInsercaoMT() {
		return insercaoMT;
	}

	public void setInsercaoMT(InsercaoMercadoTrabalho insercaoMT) {
		this.insercaoMT = insercaoMT;
	}

	public RendaFamiliar getRendaFamiliar() {
		return rendaFamiliar;
	}

	public void setRendaFamiliar(RendaFamiliar rendaFamiliar) {
		this.rendaFamiliar = rendaFamiliar;
	}

	public CuidadosConstantes getCuidadosConstantes() {
		return cuidadosConstantes;
	}

	public void setCuidadosConstantes(CuidadosConstantes cuidadosConstantes) {
		this.cuidadosConstantes = cuidadosConstantes;
	}

	public Usuario getUsuario() {
		return usuario;
	}

	public void setUsuario(Usuario usuario) {
		this.usuario = usuario;
	}

	public boolean isDeficienciaVisual() {
		return deficienciaVisual;
	}

	public void setDeficienciaVisual(boolean deficienciaVisual) {
		this.deficienciaVisual = deficienciaVisual;
	}

	public boolean isDeficienciaAuditiva() {
		return deficienciaAuditiva;
	}

	public void setDeficienciaAuditiva(boolean deficienciaAuditiva) {
		this.deficienciaAuditiva = deficienciaAuditiva;
	}

	public boolean isDeficienciaIntelectual() {
		return deficienciaIntelectual;
	}

	public void setDeficienciaIntelectual(boolean deficienciaIntelectual) {
		this.deficienciaIntelectual = deficienciaIntelectual;
	}

	public boolean isDeficienciaTranstornoMental() {
		return deficienciaTranstornoMental;
	}

	public void setDeficienciaTranstornoMental(boolean deficienciaTranstornoMental) {
		this.deficienciaTranstornoMental = deficienciaTranstornoMental;
	}

	public boolean isDeficienciaDoencaCronica() {
		return deficienciaDoencaCronica;
	}

	public void setDeficienciaDoencaCronica(boolean deficienciaDoencaCronica) {
		this.deficienciaDoencaCronica = deficienciaDoencaCronica;
	}

	public boolean isDefNeuroMusculoEsqueletica() {
		return defNeuroMusculoEsqueletica;
	}

	public void setDefNeuroMusculoEsqueletica(boolean defNeuroMusculoEsqueletica) {
		this.defNeuroMusculoEsqueletica = defNeuroMusculoEsqueletica;
	}

	public boolean isDeficienciaMultipla() {
		return deficienciaMultipla;
	}

	public void setDeficienciaMultipla(boolean deficienciaMultipla) {
		this.deficienciaMultipla = deficienciaMultipla;
	}

	public boolean isDeficienciaNaoInformada() {
		return deficienciaNaoInformada;
	}

	public void setDeficienciaNaoInformada(boolean deficienciaNaoInformada) {
		this.deficienciaNaoInformada = deficienciaNaoInformada;
	}

	public RedeEnsino getRedeEnsino() {
		return redeEnsino;
	}

	public void setRedeEnsino(RedeEnsino redeEnsino) {
		this.redeEnsino = redeEnsino;
	}

	public LocalRedeEnsino getLocalRedeEnsino() {
		return localRedeEnsino;
	}

	public void setLocalRedeEnsino(LocalRedeEnsino localRedeEnsino) {
		this.localRedeEnsino = localRedeEnsino;
	}

	public AtendimentoSus getAtendimentoSus() {
		return atendimentoSus;
	}

	public void setAtendimentoSus(AtendimentoSus atendimentoSus) {
		this.atendimentoSus = atendimentoSus;
	}

	public LocalSus getLocalSus() {
		return localSus;
	}

	public void setLocalSus(LocalSus localSus) {
		this.localSus = localSus;
	}

	public UsoMedicamento getUsoMedicamento() {
		return usoMedicamento;
	}

	public void setUsoMedicamento(UsoMedicamento usoMedicamento) {
		this.usoMedicamento = usoMedicamento;
	}

	public boolean isMedicamentoComprado() {
		return medicamentoComprado;
	}

	public void setMedicamentoComprado(boolean medicamentoComprado) {
		this.medicamentoComprado = medicamentoComprado;
	}

	public boolean isMedicamentoGratuito() {
		return medicamentoGratuito;
	}

	public void setMedicamentoGratuito(boolean medicamentoGratuito) {
		this.medicamentoGratuito = medicamentoGratuito;
	}

	public AcessoLazer getAcessoLazer() {
		return acessoLazer;
	}

	public void setAcessoLazer(AcessoLazer acessoLazer) {
		this.acessoLazer = acessoLazer;
	}

	public String getLazer() {
		return lazer;
	}

	public void setLazer(String lazer) {
		this.lazer = lazer;
	}

	public boolean isCras() {
		return cras;
	}

	public void setCras(boolean cras) {
		this.cras = cras;
	}

	public boolean isCreas() {
		return creas;
	}

	public void setCreas(boolean creas) {
		this.creas = creas;
	}

	public boolean isServicoConvivencia() {
		return servicoConvivencia;
	}

	public void setServicoConvivencia(boolean servicoConvivencia) {
		this.servicoConvivencia = servicoConvivencia;
	}

	public boolean isBeneficiosTransferenciaRenda() {
		return beneficiosTransferenciaRenda;
	}

	public void setBeneficiosTransferenciaRenda(boolean beneficiosTransferenciaRenda) {
		this.beneficiosTransferenciaRenda = beneficiosTransferenciaRenda;
	}

	public boolean isCadunico() {
		return cadunico;
	}

	public void setCadunico(boolean cadunico) {
		this.cadunico = cadunico;
	}

	public boolean isBeneficiosEventuais() {
		return beneficiosEventuais;
	}

	public void setBeneficiosEventuais(boolean beneficiosEventuais) {
		this.beneficiosEventuais = beneficiosEventuais;
	}

	public boolean isCentroPop() {
		return centroPop;
	}

	public void setCentroPop(boolean centroPop) {
		this.centroPop = centroPop;
	}

	public boolean isAlbergue() {
		return albergue;
	}

	public void setAlbergue(boolean albergue) {
		this.albergue = albergue;
	}
	
	public boolean isSemAcessoPoliticaSocial() {
		return semAcessoPoliticaSocial;
	}

	public void setSemAcessoPoliticaSocial(boolean semAcessoPoliticaSocial) {
		this.semAcessoPoliticaSocial = semAcessoPoliticaSocial;
	}

	public AcessoTransportePublico getAcessoTransportePublico() {
		return acessoTransportePublico;
	}

	public void setAcessoTransportePublico(AcessoTransportePublico acessoTransportePublico) {
		this.acessoTransportePublico = acessoTransportePublico;
	}

	public TransporteAdaptado getTransporteAdaptado() {
		return transporteAdaptado;
	}

	public void setTransporteAdaptado(TransporteAdaptado transporteAdaptado) {
		this.transporteAdaptado = transporteAdaptado;
	}

	public TransporteGratuito getTransporteGratuito() {
		return transporteGratuito;
	}

	public void setTransporteGratuito(TransporteGratuito transporteGratuito) {
		this.transporteGratuito = transporteGratuito;
	}

	public boolean isInternet() {
		return internet;
	}

	public void setInternet(boolean internet) {
		this.internet = internet;
	}

	public boolean isComputador() {
		return computador;
	}

	public void setComputador(boolean computador) {
		this.computador = computador;
	}

	public boolean isTelevisao() {
		return televisao;
	}

	public void setTelevisao(boolean televisao) {
		this.televisao = televisao;
	}

	public boolean isCelular() {
		return celular;
	}

	public void setCelular(boolean celular) {
		this.celular = celular;
	}

	public boolean isRadio() {
		return radio;
	}

	public void setRadio(boolean radio) {
		this.radio = radio;
	}

	public boolean isSemAcesso() {
		return semAcesso;
	}

	public void setSemAcesso(boolean semAcesso) {
		this.semAcesso = semAcesso;
	}

	public ConhecimentoBPC getConhecimentoBPC() {
		return conhecimentoBPC;
	}

	public void setConhecimentoBPC(ConhecimentoBPC conhecimentoBPC) {
		this.conhecimentoBPC = conhecimentoBPC;
	}

	public EscolhaAPS getEscolhaAPS() {
		return escolhaAPS;
	}

	public void setEscolhaAPS(EscolhaAPS escolhaAPS) {
		this.escolhaAPS = escolhaAPS;
	}

	public String getAvaliacao() {
		return avaliacao;
	}

	public void setAvaliacao(String avaliacao) {
		this.avaliacao = avaliacao;
	}
	
	public String getParecer() {
		return parecer;
	}

	public void setParecer(String parecer) {
		this.parecer = parecer;
	}
	
	public String getTelefone() {
		return telefone;
	}

	public void setTelefone(String telefone) {
		this.telefone = telefone;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((codigo == null) ? 0 : codigo.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Ciu other = (Ciu) obj;
		if (codigo == null) {
			if (other.codigo != null)
				return false;
		} else if (!codigo.equals(other.codigo))
			return false;
		return true;
	}

	
	
	
	
	/*@NotNull
	@Enumerated(EnumType.STRING)
	private TipoCiu tipo;*/
	
	/*@NotNull
	@NumberFormat(pattern = "#,##0.00")
	private BigDecimal valor;*/


}
