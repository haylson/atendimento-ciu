package com.acre.ciu.controller;

import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.acre.ciu.model.AcessoLazer;
import com.acre.ciu.model.AcessoTransportePublico;
import com.acre.ciu.model.AtendimentoSus;
import com.acre.ciu.model.Ciu;
import com.acre.ciu.model.ConhecimentoBPC;
import com.acre.ciu.model.Cor;
import com.acre.ciu.model.CuidadosConstantes;
import com.acre.ciu.model.Escolaridade;
import com.acre.ciu.model.EscolhaAPS;
import com.acre.ciu.model.EspecificidadeSocial;
import com.acre.ciu.model.EstadoCivil;
import com.acre.ciu.model.FaixaEtaria;
import com.acre.ciu.model.InsercaoMercadoTrabalho;
import com.acre.ciu.model.LocalRedeEnsino;
import com.acre.ciu.model.LocalSus;
import com.acre.ciu.model.RedeEnsino;
import com.acre.ciu.model.RendaFamiliar;
import com.acre.ciu.model.Sexo;
import com.acre.ciu.model.Situacao;
import com.acre.ciu.model.TransporteAdaptado;
import com.acre.ciu.model.TransporteGratuito;
import com.acre.ciu.model.UsoMedicamento;
import com.acre.ciu.model.Usuario;
import com.acre.ciu.model.VinculoEmpregaticio;
import com.acre.ciu.repository.CiuRepository;
import com.acre.ciu.repository.filter.CiuFilter;
import com.acre.ciu.service.UsuarioService;

@Controller
public class CiuController {
	
	@Autowired
	private CiuRepository ciuRepository;
	
	@Autowired
	private UsuarioService usuarioService;
	
	@GetMapping("/")
	public ModelAndView index() {
		ModelAndView mv = new ModelAndView("index");
		return mv;
	}
	
	User user;
	
	@GetMapping("/ciu/novo")
	public ModelAndView novo(Ciu ciu) {
		
		Usuario usuarioLogado = usuarioService.pegarUsuarioLogado();
		
		ciu.setUsuario(usuarioLogado);
		
		Usuario usuario = ciu.getUsuario();
		
		if(usuario == null){
			ciu.setUsuario(usuarioService.pegarUsuarioLogado());
		}
		
		ModelAndView mv = new ModelAndView("ciu/cadastro-ciu");
		mv.addObject(ciu);
		mv.addObject("usuario", ciu.getUsuario());
		mv.addObject("situacoes", Situacao.values());
		mv.addObject("sexos", Sexo.values());
		mv.addObject("estadosCivis", EstadoCivil.values());
		mv.addObject("faixasEtarias", FaixaEtaria.values());
		mv.addObject("cores", Cor.values());
		mv.addObject("especificidades", EspecificidadeSocial.values());
		mv.addObject("escolaridades", Escolaridade.values());
		mv.addObject("vinculosEmpregaticios", VinculoEmpregaticio.values());
		mv.addObject("insercoesMT", InsercaoMercadoTrabalho.values());
		mv.addObject("rendas", RendaFamiliar.values());
		mv.addObject("cuidados", CuidadosConstantes.values());
		mv.addObject("deficienciaVisual", ciu.isDeficienciaVisual());
		mv.addObject("deficienciaAuditiva", ciu.isDeficienciaAuditiva());
		mv.addObject("deficienciaIntelectual", ciu.isDeficienciaIntelectual());
		mv.addObject("deficienciaTranstornoMental", ciu.isDeficienciaTranstornoMental());
		mv.addObject("deficienciaDoencaCronica", ciu.isDeficienciaDoencaCronica());
		mv.addObject("defNeuroMusculoEsqueletica", ciu.isDefNeuroMusculoEsqueletica());
		mv.addObject("deficienciaMultipla", ciu.isDeficienciaMultipla());
		mv.addObject("deficienciaNaoInformada", ciu.isDeficienciaNaoInformada());
		mv.addObject("redesEnsino", RedeEnsino.values());
		mv.addObject("locaisRedeEnsino", LocalRedeEnsino.values());
		mv.addObject("atendimentosSus", AtendimentoSus.values());
		mv.addObject("locaisSus", LocalSus.values());
		mv.addObject("usosMedicamento", UsoMedicamento.values());
		mv.addObject("medicamentoComprado", ciu.isMedicamentoComprado());
		mv.addObject("medicamentoGratuito", ciu.isMedicamentoGratuito());
		mv.addObject("acessosLazer", AcessoLazer.values());
		mv.addObject("cras", ciu.isCras());
		mv.addObject("creas", ciu.isCreas());
		mv.addObject("servicoConvivencia", ciu.isServicoConvivencia());
		mv.addObject("beneficiosTransferenciaRenda", ciu.isBeneficiosTransferenciaRenda());
		mv.addObject("cadunico", ciu.isCadunico());
		mv.addObject("beneficiosEventuais", ciu.isBeneficiosEventuais());
		mv.addObject("centroPop", ciu.isCentroPop());
		mv.addObject("albergue", ciu.isAlbergue());
		mv.addObject("semAcessoPoliticaSocial", ciu.isSemAcessoPoliticaSocial());
		mv.addObject("acessosTransportePublico", AcessoTransportePublico.values());
		mv.addObject("transportesAdaptado", TransporteAdaptado.values());
		mv.addObject("transportesGratuito", TransporteGratuito.values());
		mv.addObject("internet", ciu.isInternet());
		mv.addObject("computador", ciu.isComputador());
		mv.addObject("televisao", ciu.isTelevisao());
		mv.addObject("celular", ciu.isCelular());
		mv.addObject("radio", ciu.isRadio());
		mv.addObject("semAcesso", ciu.isSemAcesso());
		mv.addObject("conhecimentosBPC", ConhecimentoBPC.values());
		mv.addObject("escolhasAPS", EscolhaAPS.values());
		
		return mv;
	}
	
	@PostMapping("/ciu/novo")
	public ModelAndView salvar(@Valid Ciu ciu, BindingResult result, RedirectAttributes attributes) {
		
		if(result.hasErrors()) {
			return novo(ciu);
		}
		
		ciuRepository.save(ciu);
		attributes.addFlashAttribute("mensagemSucesso", "Cadastro salvo com sucesso!");
		return new ModelAndView("redirect:/ciu/novo");
	}
	
	@GetMapping("/ciu/pesquisa")
	public ModelAndView pesquisar(CiuFilter ciuFilter) {
		ModelAndView mv = new ModelAndView("ciu/pesquisa-ciu");
		mv.addObject("cius", ciuRepository.findByCpfContainingIgnoreCase(
			Optional.ofNullable(ciuFilter.getCpf()).orElse("%")));
		return mv;
	}
	
	@GetMapping("/ciu/{codigo}")
	public ModelAndView editar(@PathVariable Long codigo) {
		Ciu ciu = ciuRepository.findOne(codigo);
		return novo(ciu);
	}
	
	@DeleteMapping("/ciu/{codigo}")
	public String apagar(@PathVariable Long codigo, RedirectAttributes attributes) {
		ciuRepository.delete(codigo);
		attributes.addFlashAttribute("mensagemExclusao", "CIU removido com sucesso!");
		return "redirect:/ciu/pesquisa";
	}
	
	

}
