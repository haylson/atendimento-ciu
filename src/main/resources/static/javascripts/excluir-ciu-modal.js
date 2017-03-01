$('#confirmaExclusaoModal').on('show.bs.modal', function (event) {
	var botao = $(event.relatedTarget);
	var codigo = botao.data('codigo');
	var url = botao.data('url-apagar');
	
	var modal = $(this);
	var form = modal.find('form');
	form.attr('action', url);
	modal.find('.modal-body span').html('Tem certeza que deseja excluir o CIU de código: <strong>' + codigo + '</strong>?');
});